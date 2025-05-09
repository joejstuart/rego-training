from langchain.chat_models import ChatOpenAI
from langchain.agents import load_tools, initialize_agent, Tool
from langchain.memory import ConversationBufferMemory
import os
from dotenv import load_dotenv
from tools.jira import search_jira, create_jira_issue

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

jira_tools = [
    Tool(
        name="jira-search",
        func=search_jira,
        description="Use this to search Jira with a JQL query. Input should be the JQL string.",
    ),
    Tool(
        name="jira-create",
        func=create_jira_issue,
        description="Use this to create a Jira issue. Input should be a comma‑separated string: project_key, summary, description.",
    ),
]

tools  = load_tools(["llm-math"], llm=llm) + jira_tools
memory = ConversationBufferMemory(memory_key="chat_history", return_messages=True)

agent = initialize_agent(
    tools=tools,
    llm=llm,
    agent="conversational-react-description",
    memory=memory,
    verbose=True,
    agent_kwargs={
        "prefix": "You are Granite‑3.2‑8b‑instruct, a reasoning expert.\n\n{chat_history}\nHuman: {input}\nAssistant:",
        # you can also override format_instructions and suffix here if you want
    },
)

if __name__ == "__main__":
    while True:
        q = input("You: ")
        if q.lower() in ("exit", "quit"):
            break
        print("AI:", agent.run(q))

