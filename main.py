from langchain.chat_models import ChatOpenAI
from langchain.agents import load_tools, initialize_agent
from langchain.memory import ConversationBufferMemory
import os
from dotenv import load_dotenv

load_dotenv()
MODEL_API = os.environ["MODEL_API"]
MODEL_ID  = os.environ["MODEL_ID"]
USER_KEY  = os.environ["USER_KEY"]

llm = ChatOpenAI(
    model_name=MODEL_ID,
    openai_api_base=MODEL_API,
    openai_api_key=USER_KEY,
    temperature=0.7,
)

tools  = load_tools(["llm-math"], llm=llm)
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

print(MODEL_API)

if __name__ == "__main__":
    while True:
        q = input("You: ")
        if q.lower() in ("exit", "quit"):
            break
        print("AI:", agent.run(q))

