from langchain_community.chat_models import ChatOpenAI
from langchain.agents import Tool, AgentExecutor, create_react_agent
from langchain.memory import ConversationBufferMemory
from langchain.prompts import PromptTemplate
from langchain.schema import HumanMessage
from langchain_experimental.utilities import PythonREPL
from langchain_community.utilities import DuckDuckGoSearchAPIWrapper
from langchain_core._api.deprecation import LangChainDeprecationWarning
import os
import re
import warnings
import PyPDF2
from dotenv import load_dotenv
from tools.jira import search_jira, create_jira_issue, fetch_jira_descriptions

warnings.filterwarnings("ignore", category=LangChainDeprecationWarning)

# ─── Load Environment ────────────────────────────────────────────────────────
load_dotenv()
MODEL_API = os.environ["MODEL_API"]
MODEL_ID  = os.environ["MODEL_ID"]
USER_KEY  = os.environ["USER_KEY"]

# ─── LLM Setup ───────────────────────────────────────────────────────────────
llm = ChatOpenAI(
    model_name=MODEL_ID,
    openai_api_base=MODEL_API,
    openai_api_key=USER_KEY,
    temperature=0.7,
)

# ─── Custom Tools ────────────────────────────────────────────────────────────
def summarize_jira(jql: str) -> str:
    blob = fetch_jira_descriptions(jql)
    prompt = (
        "Below are Jira issue descriptions:\n\n"
        f"{blob}\n\n"
        "Please provide a concise summary of the main themes and any common blockers or patterns."
    )
    msg = HumanMessage(content=prompt)
    return llm([msg]).content

def format_jira_ac(arg: str) -> str:
    prompt = f"""
You are an expert Jira issue writer.
Acronyms:
- EC = Enterprise Contract
- VSA = Verification Summary Attestation

Raw details: {arg.strip()}

Generate exactly this format from the raw details. The acceptance criteria should be concise and guide the developer on the desired behavior of the feature.

Summary: <one-line, imperative summary>

Acceptance Criteria:
- <criterion 1>
- <criterion 2>
"""
    msg = HumanMessage(content=prompt)
    return llm([msg]).content

def get_structured_headlines(query: str, count: int = 3) -> str:
    ddg = DuckDuckGoSearchAPIWrapper()
    raw_results = ddg.run(query)

    # Try to split by newlines or bullet points to isolate entries
    items = re.split(r"\n|•|- ", raw_results)
    cleaned = [i.strip() for i in items if len(i.strip()) > 40]  # Filter short/noisy lines

    # Extract up to `count` headlines that look like real news
    headlines = []
    for item in cleaned:
        # Try to extract a source name in parentheses
        source_match = re.search(r"\b(from|on)\s([A-Z][a-zA-Z]+(\sNews)?\b)", item)
        source = f"({source_match.group(2)})" if source_match else ""
        headline = re.sub(r'\s+', ' ', item).strip()
        headlines.append(f"{len(headlines)+1}. {headline} {source}")
        if len(headlines) == count:
            break

    if not headlines:
        return "Could not extract any real headlines. Try refining your query."

    return "\n".join(headlines)

def summarize_pdf(file_path: str) -> str:
    # Step 1: Extract text
    # chop newline from file_path
    file_path = file_path.rstrip()
    with open(file_path, "rb") as f:
        reader = PyPDF2.PdfReader(f)
        raw_text = "\n".join([page.extract_text() or "" for page in reader.pages])

    if not raw_text.strip():
        return "Could not extract any text from the PDF."

    # Step 2: Summarize
    summary_prompt = f"""
Summarize the following PDF content into concise, clear bullet points. Focus on key takeaways.

Content:
{raw_text}
"""
    return llm([HumanMessage(content=summary_prompt)]).content


# ─── Tool List ───────────────────────────────────────────────────────────────
jira_tools = [
    Tool(
        name="jira-search",
        func=search_jira,
        description="Search Jira with a JQL query. All strings must be quoted (e.g., status = \"Done\")."
    ),
    Tool(
        name="jira-create",
        func=create_jira_issue,
        description="Create a Jira issue. Input format: project_key, summary, description."
    ),
    Tool(
        name="jira-summarize",
        func=summarize_jira,
        description="Summarize Jira issue descriptions matching a JQL query."
    ),
    Tool(
        name="jira-format-ac",
        func=format_jira_ac,
        description="Format raw issue text into a summary and acceptance criteria. Input should be free-form text."
    ),
]

repl_tool = Tool(
    name="python_repl",
    func=PythonREPL().run,
    description="Execute Python code and return the result. Use print(...) to show output."
)

web_search_tool = Tool(
    name="web-search",
    func=DuckDuckGoSearchAPIWrapper().run,
    description=(
        "Search the web using DuckDuckGo. Use this tool to find *real headlines or articles* related to news, current events, or specific topics. "
        "Summarize the actual content, not just the website names. Avoid listing only sources."
    ),
)

news_search_tool = Tool(
    name="news-search",
    func=get_structured_headlines,
    description="Search the web for real news headlines. Use this tool to find *real headlines or articles* related to news, current events, or specific topics. "
    "Summarize the actual content, not just the website names. Avoid listing only sources."
)

pdf_tool = Tool(
    name="summarize-pdf",
    func=summarize_pdf,
    description="Summarize a PDF file from disk. Input should be the full file path to a .pdf file."
)

tools = [repl_tool, web_search_tool, news_search_tool, pdf_tool] + jira_tools

# ─── ReAct Prompt Template ───────────────────────────────────────────────────
prompt_template = """You are a helpful AI assistant that uses tools and thinks step-by-step.

You can use the following tools:
{tools}

Use this format:

Question: the user's question
Thought: your reasoning
Action: the action to take, consider using the tools if necessary [{tool_names}]
Action Input: the input to the action
Observation: the result
... (you can repeat Thought/Action/Observation as needed)
Thought: Do I have enough information?

If yes:
Final Answer: your final answer

Important:
- Once you write Final Answer, you must stop. Do not continue with more thoughts or actions.
- Only use tools when necessary. If you already have enough information, skip tool use.

Begin!

Question: {input}
{agent_scratchpad}
"""

prompt = PromptTemplate(
    template=prompt_template,
    input_variables=["input", "agent_scratchpad", "tool_names"],
)

# ─── Agent Setup ─────────────────────────────────────────────────────────────
memory = ConversationBufferMemory(memory_key="chat_history", return_messages=True)

react_agent = create_react_agent(llm=llm, tools=tools, prompt=prompt)

agent = AgentExecutor.from_agent_and_tools(
    agent=react_agent,
    tools=tools,
    memory=memory,
    verbose=True,
    handle_parsing_errors=True,
    max_iterations=6,
)

# ─── Interactive Loop ────────────────────────────────────────────────────────
if __name__ == "__main__":
    while True:
        try:
            q = input("You: ")
            if q.lower() in ("exit", "quit"):
                break
            result = agent.invoke({"input": q})
            print("AI:", result["output"])
        except Exception as e:
            print("\n❌ Agent Error:", str(e))
