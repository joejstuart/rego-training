from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.schema import HumanMessage
import os

load_dotenv()

llm = ChatOpenAI(
    model_name=os.environ["MODEL_ID"],
    openai_api_base=os.environ["MODEL_API"],
    openai_api_key=os.environ["USER_KEY"],
    temperature=0.3,
)

msg = HumanMessage(content="Say hello.")
print("Sending request...")
response = llm.invoke([msg])
print("✅ LLM responded:", response.content if response else "⚠️ Nothing returned")
