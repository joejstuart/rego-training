from langchain.chat_models import ChatOpenAI
from langchain.agents import load_tools, initialize_agent, Tool
from langchain.memory import ConversationBufferMemory
from langchain.schema import HumanMessage
from langchain_experimental.utilities import PythonREPL
import os
from dotenv import load_dotenv
from tools.jira import search_jira, create_jira_issue, fetch_jira_descriptions

load_dotenv()
MODEL_API = os.environ["MODEL_API"]
MODEL_ID  = os.environ["MODEL_ID"]
USER_KEY  = os.environ["USER_KEY"]


# uses /v1/chat/completions
llm = ChatOpenAI(
    model_name=MODEL_ID,
    openai_api_base=MODEL_API,
    openai_api_key=USER_KEY,
    temperature=0.7,
)

# ─── helper that ties JQL → descriptions → LLM summary ────────────────────────
def summarize_jira(jql: str) -> str:
    """
    Tool: run the JQL, pull descriptions, and ask the LLM to summarize them.
    """
    blob = fetch_jira_descriptions(jql)
    prompt = (
        "Below are Jira issue descriptions:\n\n"
        f"{blob}\n\n"
        "Please provide a concise summary of the main themes and "
        "any common blockers or patterns."
    )
    # send as a single chat message
    msg = HumanMessage(content=prompt)
    return llm([msg]).content

# ─── Helper to generate a polished summary + AC without creating an issue ────
def format_jira_ac(arg: str) -> str:
    """
    Input: free-form raw issue details.
    Output: a polished one-line Summary and a bullet-list Acceptance Criteria.
    """

    prompt = f"""
You are an expert Jira issue writer.
Acronyms:
- EC = Enterprise Contract
- VSA = Verification Summary Attestation

Raw details: {arg.strip()}

Generate exactly this format. **The acceptance criteria should be concise and guide the developer on the desired behavior of the feature.**

Summary: <one-line, imperative summary>

Acceptance Criteria:
- <concise criterion 1>
- <concise criterion 2>
- ...
"""
    # call the LLM with a HumanMessage
    msg = HumanMessage(content=prompt)
    return llm([msg]).content

# jira tools
jira_tools = [
    Tool(
        name="jira-search",
        func=search_jira,
        description="Use this to search Jira with a JQL query. Input should be the JQL string.",
    ),
    Tool(
        name="jira-create",
        func=create_jira_issue,
        description="Use this to create a Jira issue. Input should be a comma-separated string: project_key, summary, description.",
    ),
    Tool(
        name="jira-summarize",
        func=summarize_jira,
        description="Use this to summarize Jira issues. Input should be a JQL query.",
    ),
    Tool(
        name="jira-format-ac",
        func=format_jira_ac,
        description=(
            "Generate a polished summary and acceptance criteria from raw issue details."
            "Input should be the free-form issue description."
        ),
    ),
]

# python repl tool
python_repl = PythonREPL()
repl_tool = Tool(
    name="python_repl",
    description="A Python shell. Use this to execute python commands. Input should be a valid python command. If you want to see the output of a value, you should print it out with `print(...)`.",
    func=python_repl.run,
)

tools = [repl_tool] + jira_tools

memory = ConversationBufferMemory(memory_key="chat_history", return_messages=True)

agent = initialize_agent(
    tools=tools,
    llm=llm,
    agent="conversational-react-description",
    memory=memory,
    verbose=True,
    agent_kwargs={
        "prefix": "You are Granite-3.2-8b-instruct, a reasoning expert.\n\n{chat_history}\nHuman: {input}\nAssistant:",
        # you can also override format_instructions and suffix here if you want
    },
)

if __name__ == "__main__":
    while True:
        q = input("You: ")
        if q.lower() in ("exit", "quit"):
            break
        print("AI:", agent.run(q))
