#!/usr/bin/env python3
import argparse
import os
import subprocess
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.schema import HumanMessage

# ─── Load Granite Environment ────────────────────────────────────────────────
load_dotenv()
MODEL_API = os.getenv("MODEL_API")
MODEL_ID = os.getenv("MODEL_ID")
USER_KEY = os.getenv("USER_KEY")

if not MODEL_API or not MODEL_ID or not USER_KEY:
    raise ValueError("Missing MODEL_API, MODEL_ID, or USER_KEY in environment.")

# ─── LLM Setup ───────────────────────────────────────────────────────────────
llm = ChatOpenAI(
    model_name=MODEL_ID,
    openai_api_base=MODEL_API,
    openai_api_key=USER_KEY,
    temperature=0.3,
)

# ─── Prompt Template ─────────────────────────────────────────────────────────
PROMPT_TEMPLATE = """
You are a code quality assistant.

Review the following Git commit message for clarity, structure, and best practices that help both humans and AI understand the intent and implementation.

Best practices:
- One-line imperative summary (e.g., Add X, Fix Y)
- Optional body explaining what changed, why, and how
- Lists of files/functions/impacts are helpful
- References to issues, components, or features
- Avoid vague terms like "stuff", "trying", "fixes something"

Commit message:
---
{commit}
---

Respond with:
- ✅ if the message is good
- ❌ if it could be improved, followed by specific suggestions

Your review:
"""
# ─── Functions ───────────────────────────────────────────────────────────────
def get_commit_diff_and_message(sha: str, repo_dir: str) -> tuple[str, str]: 
    try:
        message = subprocess.check_output(
            ["git", "show", "-s", "--format=%B", sha],
            stderr=subprocess.STDOUT,
            text=True,
            cwd=repo_dir  # ✅ point Git at the repo
        ).strip()

        diff = subprocess.check_output(
            ["git", "show", sha, "--no-color", "--unified=1"],
            stderr=subprocess.STDOUT,
            text=True,
            cwd=repo_dir  # ✅ point Git at the repo
        ).strip()

        if not message:
            raise ValueError(f"No commit message found for SHA: {sha}")
        if not diff:
            raise ValueError(f"No diff found for SHA: {sha}")

        # Truncate large diffs to first N lines
        max_lines = 500
        diff_lines = diff.splitlines()
        if len(diff_lines) > max_lines:
            diff = "\n".join(diff_lines[:max_lines]) + "\n\n[Diff truncated after 500 lines]"

        return message, diff

    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Git error while accessing SHA {sha}:\n{e.output}")


def get_commit_message_from_sha(sha: str, repo_dir: str) -> str:
    try:
        result = subprocess.check_output(
            ["git", "show", "-s", "--format=%B", sha],
            stderr=subprocess.DEVNULL,
            text=True,
            cwd=repo_dir  # ✅
        )
        return result.strip()
    except subprocess.CalledProcessError:
        raise RuntimeError(f"Failed to retrieve commit message for SHA: {sha}")

def review_commit_message(message: str, diff: str | None = None) -> str:
    if diff:
        prompt = f"""
You are a software development assistant.

This is a Git commit with the following message:
---
{message}
---

And the following code changes (diff):
---
{diff}
---

Evaluate whether the message accurately describes what changed. If it's good, say ✅ and explain why. If it's vague or incomplete, say ❌ and suggest a clearer message, including a one-line summary and optionally a body.

Return your suggestion in markdown format.

Begin.
"""
    else:
        prompt = PROMPT_TEMPLATE.format(commit=message)

    try:
        response = llm.invoke([HumanMessage(content=prompt)])
        if not response or not getattr(response, "content", "").strip():
            return "❌ LLM returned no content. Prompt may be too long or malformed."
        return response.content
    except Exception as e:
        return f"❌ LLM Error: {str(e)}"


def main():
    parser = argparse.ArgumentParser(description="LLM commit message checker using Granite.")
    parser.add_argument("--commit", type=str, help="The raw commit message text.")
    parser.add_argument("--sha", type=str, help="The commit SHA to look up the message and diff.")
    parser.add_argument("--fail-on-error", action="store_true", help="Exit with 1 if message is invalid or could be improved.")
    parser.add_argument(
        "--repo",
        type=str,
        default=".",
        help="Path to the Git repository (default: current directory)"
    )

    args = parser.parse_args()

    if not args.commit and not args.sha:
        print("❌ Provide either --commit or --sha")
        exit(1)

    try:
        if args.sha:
            commit_msg, commit_diff = get_commit_diff_and_message(args.sha, args.repo)
            print(f"🔍 Reviewing commit {args.sha} with LLM...\n")
            result = review_commit_message(commit_msg, commit_diff)
        else:
            print("🔍 Checking commit message with LLM...\n")
            result = review_commit_message(args.commit)

        print("🧠 LLM Response:")
        print(result or "⚠️ No response returned.")

        if "❌" in result and args.fail_on_error:
            exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        exit(1)

if __name__ == "__main__":
    main()


