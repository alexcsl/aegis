"""OpenAI Agents SDK integration example.

Shows how to wrap tools used with the OpenAI Agents SDK using the async
AsyncAegis client — the natural fit since the Agents SDK is async-first.

Requirements:
    pip install aegis-sdk openai-agents
"""

import asyncio
from agents import Agent, Runner, function_tool

from aegis import AsyncAegis, DeniedError


# ---------------------------------------------------------------------------
# 1. Create the async Aegis client
# ---------------------------------------------------------------------------

aegis = AsyncAegis(
    agent_id="openai-agents-demo",
    # api_key and url read from AEGIS_API_KEY / AEGIS_URL env vars
)


# ---------------------------------------------------------------------------
# 2. Wrap tools with @aegis.wrap as a decorator
# ---------------------------------------------------------------------------

@function_tool
@aegis.wrap
async def search_web(query: str) -> str:
    """Search the web for information."""
    return f"[mock results for: {query}]"


@function_tool
@aegis.wrap
async def delete_file(path: str) -> str:
    """Delete a file from the filesystem."""
    import os
    os.remove(path)
    return f"deleted: {path}"


@function_tool
@aegis.wrap
async def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to the given recipient."""
    # The policy can DEFER this for human approval before sending
    return f"email sent to {to}"


# ---------------------------------------------------------------------------
# 3. Create and run the agent
# ---------------------------------------------------------------------------

agent = Agent(
    name="demo-agent",
    instructions="You are a helpful assistant. Use the provided tools when needed.",
    tools=[search_web, delete_file, send_email],
)


async def main() -> None:
    async with aegis:  # closes the HTTP client when done
        try:
            result = await Runner.run(
                agent,
                input="Search for 'asyncio best practices'.",
            )
            print(result.final_output)
        except DeniedError as e:
            # Aegis blocked a tool call — surface it cleanly
            print(f"Tool call blocked by Aegis policy: {e}")


if __name__ == "__main__":
    asyncio.run(main())
