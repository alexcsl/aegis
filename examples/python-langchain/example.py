"""LangChain tool integration example.

Shows how to wrap LangChain tools with Aegis policy enforcement using
the synchronous Aegis client, which works from both sync and async LangChain
contexts without nest_asyncio hacks.

Requirements:
    pip install aegis-sdk langchain langchain-openai
"""

import os
from langchain.tools import tool
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate

from aegis import Aegis, DeniedError


# ---------------------------------------------------------------------------
# 1. Create the Aegis client
# ---------------------------------------------------------------------------

aegis = Aegis(
    agent_id="langchain-demo",
    # api_key and url read from AEGIS_API_KEY / AEGIS_URL env vars
)


# ---------------------------------------------------------------------------
# 2. Wrap individual LangChain tools with @aegis.wrap
# ---------------------------------------------------------------------------

@tool
@aegis.wrap
def search_web(query: str) -> str:
    """Search the web for information."""
    # Real implementation would call a search API
    return f"[mock results for: {query}]"


@tool
@aegis.wrap
def delete_file(path: str) -> str:
    """Delete a file from the filesystem."""
    os.remove(path)
    return f"deleted: {path}"


@tool
@aegis.wrap
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email."""
    # Real implementation would call an email API
    return f"email sent to {to}"


# ---------------------------------------------------------------------------
# 3. Wrap an existing tool object (wrap_all style)
# ---------------------------------------------------------------------------

def _execute_sql(query: str) -> str:
    """Execute a SQL query."""
    return f"[mock sql result for: {query}]"


safe_execute_sql = aegis.wrap(_execute_sql, name="execute_sql")


# ---------------------------------------------------------------------------
# 4. Wire up a LangChain agent
# ---------------------------------------------------------------------------

tools = [search_web, delete_file, send_email]

llm = ChatOpenAI(model="gpt-4o-mini")

prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful assistant. Use the provided tools when needed."),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])

agent = create_tool_calling_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools, verbose=True)


# ---------------------------------------------------------------------------
# 5. Run with error handling for denied calls
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # This call will be intercepted. If AEGIS policy blocks delete_file,
    # DeniedError propagates and the agent sees it as a tool error.
    try:
        result = executor.invoke({"input": "Search for 'python asyncio' on the web."})
        print(result["output"])
    except DeniedError as e:
        print(f"Aegis blocked the call: {e}")
