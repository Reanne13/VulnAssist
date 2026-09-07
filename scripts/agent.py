import os
import json
from openai import OpenAI

from rag_search import search_vulnerabilities
from check_vulnerability import find_cve, check_vulnerability, assets


# ---------------------------------------------------------
# OpenRouter client
# ---------------------------------------------------------

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.environ["OPENROUTER_API_KEY"]
)


# ---------------------------------------------------------
# Tool 1: Search vulnerabilities using RAG
# ---------------------------------------------------------

def rag_search_tool(query):

    results = search_vulnerabilities(
        query,
        number_of_results=5
    )

    output = []

    for i, document in enumerate(
        results["documents"][0]
    ):

        metadata = results["metadatas"][0][i]

        output.append({
            "cve_id": metadata["cve_id"],
            "severity": metadata["severity"],
            "score": metadata["score"],
            "document": document
        })

    return output


# ---------------------------------------------------------
# Tool 2: Check a CVE against all assets
# ---------------------------------------------------------

def check_cve_against_assets(cve_id):

    vulnerability = find_cve(cve_id)

    if vulnerability is None:
        return {
            "error": f"{cve_id} was not found."
        }

    affected_assets = []

    for asset in assets:

        result = check_vulnerability(
            asset,
            vulnerability
        )

        if result["vulnerable"]:

            affected_assets.append({
                "asset_id": asset["asset_id"],
                "asset_name": asset["asset_name"],
                "owner": asset["owner"],
                "environment": asset["environment"],
                "hosting": (
                    asset["hosting"]["provider"]
                    if asset["hosting"]["type"] == "cloud"
                    else "On-Premises"
                ),
                "product": result["product"],
                "version": result["version"],
                "reason": result["reason"]
            })

    return {
        "cve_id": cve_id,
        "severity": vulnerability["cvss"]["severity"],
        "score": vulnerability["cvss"]["score"],
        "affected_assets": affected_assets
    }


# ---------------------------------------------------------
# AI Agent tools
# ---------------------------------------------------------

tools = [

    {
        "type": "function",
        "function": {
            "name": "search_vulnerabilities",
            "description": (
                "Search the vulnerability knowledge base using "
                "semantic RAG search. Use this to find CVEs "
                "relevant to the user's question."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": (
                            "The vulnerability or technology "
                            "to search for."
                        )
                    }
                },
                "required": ["query"]
            }
        }
    },

    {
        "type": "function",
        "function": {
            "name": "check_cve_against_assets",
            "description": (
                "Check a specific CVE against the organizational "
                "asset inventory and return the assets that are "
                "actually vulnerable. Vulnerability status is "
                "determined using deterministic product and "
                "version matching."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "The CVE identifier."
                    }
                },
                "required": ["cve_id"]
            }
        }
    }

]


# ---------------------------------------------------------
# Tool execution
# ---------------------------------------------------------

def execute_tool(tool_name, arguments):

    if tool_name == "search_vulnerabilities":

        return rag_search_tool(
            arguments["query"]
        )

    if tool_name == "check_cve_against_assets":

        return check_cve_against_assets(
            arguments["cve_id"]
        )

    return {
        "error": "Unknown tool"
    }


# ---------------------------------------------------------
# Agent
# ---------------------------------------------------------

def run_agent(user_question):

    messages = [

        {
            "role": "system",
            "content": """
You are VulnAssist, an AI vulnerability management assistant.

Your job is to help users identify vulnerabilities affecting
organizational assets.

You have access to two tools:

1. search_vulnerabilities
   - Uses a RAG knowledge base containing CVE information.

2. check_cve_against_assets
   - Deterministically checks CVE product and version ranges
     against the organizational asset inventory.

IMPORTANT:
- Never claim an asset is vulnerable based only on semantic RAG search.
- Always use check_cve_against_assets before stating that an
  asset is vulnerable.
- Use RAG to discover relevant CVEs and understand vulnerability
  details.
- Clearly distinguish between vulnerable and non-vulnerable assets.
- Include CVE ID, severity, CVSS score, affected asset,
  owner, environment, hosting, product and version when available.
- Provide remediation information from the retrieved vulnerability
  information when available.
- Do not invent assets, owners, versions or vulnerability details.
"""
        },

        {
            "role": "user",
            "content": user_question
        }

    ]


    while True:

        print("\nCalling AI agent...")

        response = client.chat.completions.create(

            model="minimax/minimax-m3:free",

            messages=messages,

            tools=tools,

            tool_choice="auto"
)

        message = response.choices[0].message

        if message.tool_calls:
            print("Agent requested a tool.")

        # No tool call → final answer
        if not message.tool_calls:

            return message.content

        # Add assistant's tool-call message
        messages.append(message)

        # Execute requested tools
        for tool_call in message.tool_calls:

            print(
                f"Executing tool: {tool_call.function.name}"
            )

            tool_name = tool_call.function.name

            arguments = json.loads(
                tool_call.function.arguments
            )

            result = execute_tool(
                tool_name,
                arguments
            )

            messages.append({

                "role": "tool",

                "tool_call_id": tool_call.id,

                "content": json.dumps(
                    result
                )

            })

            


# ---------------------------------------------------------
# Run the agent
# ---------------------------------------------------------

if __name__ == "__main__":

    print("\n" + "=" * 60)
    print("VULNASSIST AI AGENT")
    print("=" * 60)

    question = input(
        "\nAsk VulnAssist: "
    )

    answer = run_agent(question)

    print("\n" + "=" * 60)
    print("VULNASSIST RESPONSE")
    print("=" * 60)

    print("\n" + answer)