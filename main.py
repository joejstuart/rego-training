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
    """
    Summarize the Jira issues matching the JQL query.
    """
    blob = fetch_jira_descriptions(jql)
    prompt = f"""
You are a seasoned project manager composing the weekly status update.

Here are this week's Jira issues, separated by status:
{blob}

Your task: Write a concise narrative summary that MUST follow this exact structure:
The tone should be casual and conversational.

1. Start with a brief overview paragraph that captures the main themes of the week's work. This paragraph should be concise and to the point.
2. Follow with two main sections:
   a. Completed Work: Summarize the finished work
   b. Work In Progress: Summarize the ongoing work
3. For each section:
   - Use past tense for completed work
   - Use present/future tense for ongoing work
   - Include the impact or benefit
   - Omit issue numbers unless specifically relevant
   - Focus on telling a cohesive story about the work done
4. Then a conclusion that summarizes the work in each section.

Example format:
    This week, the team made significant progress in infrastructure improvements and team onboarding. We streamlined our development processes and enhanced our tooling capabilities while making steady progress on ongoing initiatives.

    Completed Work:
        Our infrastructure improvements focused on release management and deployment flexibility. We decommissioned the v0.4 branch and its associated releases, which streamlined our release process. Additionally, we updated the allowed registry prefixes in konflux-release-data, enabling more flexible deployments. These changes have made our release process more efficient and adaptable.

        The team also completed several tooling enhancements:
        • Rolled out the new Sealights browser plugin and verified its functionality
        • Enabled auto-merge for Renovate/Dependabot updates to improve dependency management

    Work In Progress:
        We are currently focused on implementing the VSA (Verification Summary Attestation) feature. This work includes:
        • Developing the core functionality for generating VSAs
        • Investigating storage options in Rekor
        • Creating configuration parameters for VSA generation

    Overall, the team made significant progress in infrastructure improvements and team onboarding. We streamlined our development processes and enhanced our tooling capabilities while making steady progress on ongoing initiatives.

Now, based on the descriptions above, write your summary following this EXACT structure:
"""
    msg = HumanMessage(content=prompt)
    return llm([msg]).content


def format_jira_ac(arg: str) -> str:
    prompt = f"""
You are an expert Jira issue writer.  
Acronyms:  
- EC = Enterprise Contract  
- VSA = Verification Summary Attestation  

Raw details: {arg.strip()}  

Task:
1. Write a one-line, imperative Summary.  
2. Generate 3-5 concise Acceptance Criteria that each:  
   • Describe a single, testable outcome  
   • Are phrased from at least two perspectives (user/developer)  
   • Are unique—if any two criteria overlap in meaning, include only one  

Consider Perspectives:
- **End user**: clarity and error feedback  
- **Developer**: API contract and performance  

Format exactly as follows (no extra sections):

Summary: <Imperative, “As a …” phrasing optional>

Acceptance Criteria:
- <Given…When…Then…> or “The system must…” statement  
- …  
- …

Tip:
- Use active voice (“The user can…”).  
- Prefer Given/When/Then for behavior-driven clarity:  
  • Given X, when Y, then Z.

Example:

Raw details: I’m a customer and I can’t find products by name when I search.

Output:
Summary: As a customer, I want to search for products by name.

Acceptance Criteria:
- Given a valid name, when I search, then matching products appear.  
- The system must return partial matches with at least three matching characters.  
- Search results must show name, image, and price. 
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
        description="""Search Jira with a JQL query. Returns a simple list of issue keys and summaries.
        ONLY use this tool for:
        - Looking up specific issues
        - Getting lists of issues
        - Checking issue status
        - Finding assigned issues
        DO NOT use this for status updates or summaries.
        - Use 'help' as the query to see example queries and JQL syntax tips
        - Common queries include: open issues, assigned issues
        - Use AND, OR, NOT to combine conditions
        - Use IN for multiple values (e.g., status IN (Open, 'In Progress'))
        - Use ~ for contains searches (e.g., summary ~ 'search term')
        - Use >=, <=, >, < for dates (e.g., created >= -7d)"""
    ),
    Tool(
        name="jira-create",
        func=create_jira_issue,
        description="Create a Jira issue. Input format: project_key, summary, description."
    ),
    Tool(
        name="jira-summarize",
        func=summarize_jira,
        description="""Get a narrative summary of Jira issues matching a JQL query.
        ALWAYS use this tool for:
        - Weekly status updates
        - Project progress summaries
        - Work period summaries
        - Any request for a narrative overview of work
        Example: jira-summarize project = EC AND status = 'In Progress'
        Returns a formatted narrative summary of the work."""
    ),
    Tool(
        name="jira-format-ac",
        func=format_jira_ac,
        description="""This is used to create the text for a single Jira issue only.
        Format:
        Summary: <one-line, imperative summary>
        Acceptance Criteria:
        - <criterion 1>
        - <criterion 2>
        """
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

If you determine you need to use a jira tool, make sure the query is in JQL format.

Guidelines for using Jira tools:
1. Use jira-search tool when:
   - Asked for a list of issues
   - Looking up specific issue details
   - Need to find issues matching certain criteria
   - Need to check issue status or assignments
   Example: "Show me all open issues" or "What issues are assigned to me?"

2. Use summarize_jira tool when:
   - Asked for status updates
   - Need a narrative summary of work over a period
   - Need a high-level overview of project progress
   - Asked for weekly/monthly summaries
   Example: "Give me a weekly status update" or "Summarize the project progress"

IMPORTANT: For ANY request about status updates, summaries, or progress reports, ALWAYS use summarize_jira, NOT jira-search.

When using Jira queries (JQL), follow these guidelines:
1. For weekly status updates, use: project = EC AND issuetype IN (Bug, Story, Task) AND (status = 'In Progress' OR (status = Closed AND resolved >= -1w))
2. For open issues: project = EC AND status = Open
3. For assigned issues: project = EC AND assignee = currentUser()
4. For current sprint: project = EC AND sprint in openSprints()
5. For high priority: project = EC AND priority = High

JQL Syntax Tips:
- Use AND, OR, NOT to combine conditions
- Use IN for multiple values: status IN (Open, 'In Progress')
- Use = for exact matches
- Use ~ for contains: summary ~ "search term"
- Use >=, <=, >, < for dates: created >= -7d
- Use currentUser() for the current user
- Use openSprints() for current sprint

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
- When searching Jira, use appropriate JQL queries based on the user's needs.
- REMEMBER: For status updates and summaries, ALWAYS use summarize_jira, not jira-search.

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
