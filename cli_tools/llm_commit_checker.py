#!/usr/bin/env python3
import argparse
import os
import subprocess
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.schema import HumanMessage
import warnings
from langchain_core._api.deprecation import LangChainDeprecationWarning
import textwrap

# Suppress LangChain deprecation warnings
warnings.filterwarnings("ignore", category=LangChainDeprecationWarning)

# ─── Load Granite Environment ────────────────────────────────────────────────
load_dotenv()
MODEL_API = os.getenv("MODEL_API")
MODEL_ID = os.getenv("MODEL_ID")
USER_KEY = os.getenv("USER_KEY")

if not (MODEL_API and MODEL_ID and USER_KEY):
    raise EnvironmentError("Missing MODEL_API, MODEL_ID, or USER_KEY in environment.")

# ─── LLM Setup ───────────────────────────────────────────────────────────────
llm = ChatOpenAI(
    model_name=MODEL_ID,
    openai_api_base=MODEL_API,
    openai_api_key=USER_KEY,
    temperature=0.0,  # deterministic
)

# ─── Prompt Templates ────────────────────────────────────────────────────────
REVIEW_PROMPT = """
You are a meticulous code quality assistant.

Below is a Git commit message and a code diff snippet. Your tasks:
1. Determine if the commit message accurately describes the change.
2. If adequate, respond with exactly and nothing more:
   ✅ The commit message accurately describes the changes.
3. If inadequate, respond with:
   ❌ A brief critique.
   ### Suggested Commit Message
   Summary: A concise, imperative summary (<=50 characters).
   Body:
     - What was changed and why.
     - Files or functions modified.
     - References (URLs only if present in diff).

Key constraint:
- The summary content must be at most 50 characters (excluding the "Summary: " prefix).
- Do NOT truncate mid-word or omit essential context. If the initial summary exceeds 50 characters, **rephrase** it to convey the full idea succinctly within the limit.
- Ensure every line of the output is <=50 characters.

Commit message:
---
{commit}
---

Diff snippet (truncated to 150 lines):
---
{diff}
---
"""

GENERATE_PROMPT = """
You are a proactive code quality assistant.

Given the following staged code diff, generate a high-quality Git commit message that:
- Starts with an imperative summary line (<=50 chars content).
- Includes a body explaining motivation, key changes, and file impacts.
- References relevant tickets, issues, or components (URLs only if present).

Key constraint:
- The summary content must be at most 50 characters (excluding the "Summary: " prefix).
- Do NOT truncate mid-word or omit essential context: **rephrase** the summary to fit within the limit, preserving clarity.
- Ensure every line is <=50 characters.

Diff snippet (truncated to 150 lines):
---
{diff}
---
Provide ONLY the commit message in this format:
Summary: <summary>
Body:
  - <detail>
  - <files>
  - <references>
"""

# ─── Git Helpers ─────────────────────────────────────────────────────────────
def get_commit_info(sha: str, repo_dir: str = '.') -> tuple[str, str]:
    message = subprocess.check_output([
        'git', 'show', '-s', '--format=%B', sha
    ], cwd=repo_dir, text=True, stderr=subprocess.STDOUT).strip()
    raw_diff = subprocess.check_output([
        'git', 'show', sha, '--no-color', '--unified=1'
    ], cwd=repo_dir, text=True, stderr=subprocess.STDOUT)
    lines = raw_diff.splitlines()
    snippet = '\n'.join(lines[:150])
    if len(lines) > 150:
        snippet += '\n\n[diff truncated after 150 lines]'
    return message, snippet


def get_staged_diff(repo_dir: str = '.') -> str:
    raw_diff = subprocess.check_output([
        'git', 'diff', '--staged', '--no-color', '--unified=1'
    ], cwd=repo_dir, text=True, stderr=subprocess.STDOUT)
    lines = raw_diff.splitlines()
    snippet = '\n'.join(lines[:150])
    if len(lines) > 150:
        snippet += '\n\n[diff truncated after 150 lines]'
    return snippet

# ─── Post-processing Helper ─────────────────────────────────────────────────
def wrap_to_width(text: str, width: int = 50) -> str:
    """Wrap lines to width, preserve bullets, enforce summary limit without cutting words."""
    wrapped = []
    for line in text.splitlines():
        if not line.strip():
            wrapped.append(line)
            continue
        # Summary prefix: enforce limit, no wrap, cut at word boundary
        if line.startswith('Summary: '):
            prefix = 'Summary: '
            content = line[len(prefix):]
            if len(content) > width:
                truncated = content[:width]
                # cut to last full word
                if ' ' in truncated:
                    truncated = truncated.rsplit(' ', 1)[0]
                content = truncated
            wrapped.append(prefix + content)
            continue
        # Bullet lines: wrap after dash
        if line.lstrip().startswith('- '):
            indent_marker = '  - ' if line.startswith('  - ') else '- '
            content = line[len(indent_marker):]
            subs = textwrap.wrap(content, width - len(indent_marker), break_long_words=False)
            if subs:
                wrapped.append(indent_marker + subs[0])
                indent_space = ' ' * len(indent_marker)
                for sub in subs[1:]:
                    wrapped.append(indent_space + sub)
            continue
        # Regular lines
        for sub in textwrap.wrap(line, width, break_long_words=False):
            wrapped.append(sub)
    return '\n'.join(wrapped)

# ─── LLM Functions ────────────────────────────────────────────────────────────
def review_commit(message: str, diff: str) -> str:
    prompt = REVIEW_PROMPT.format(commit=message, diff=diff)
    resp = llm.invoke([HumanMessage(content=prompt)])
    return wrap_to_width((getattr(resp, 'content', '') or '').strip())


def generate_commit_message(diff: str) -> str:
    prompt = GENERATE_PROMPT.format(diff=diff)
    resp = llm.invoke([HumanMessage(content=prompt)])
    content = (getattr(resp, 'content', '') or '').strip()
    lines = content.splitlines()
    if 'Summary:' in content:
        idx = max(i for i, l in enumerate(lines) if l.startswith('Summary:'))
        content = '\n'.join(lines[idx:])
    return wrap_to_width(content)

# ─── CLI Entrypoint ──────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='LLM commit assistant (Granite)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--commit', type=str, help='Review provided commit message')
    group.add_argument('--sha', type=str, help='Review commit by SHA')
    group.add_argument('--generate', action='store_true', help='Generate commit message from staged changes')
    parser.add_argument('--repo', type=str, default='.', help='Git repo path (default: current dir)')
    parser.add_argument('--fail-on-error', action='store_true', help='Exit 1 if review finds inadequacy')
    args = parser.parse_args()

    try:
        if args.generate:
            diff = get_staged_diff(args.repo)
            print('🔍 Generating commit message for staged changes...\n')
            result = generate_commit_message(diff)
        else:
            if args.sha:
                msg, diff = get_commit_info(args.sha, args.repo)
                print(f"🔍 Reviewing commit '{args.sha}'...\n")
            else:
                msg = args.commit
                diff = get_staged_diff(args.repo)
                print('🔍 Reviewing commit message with staged diff...\n')
            result = review_commit(msg, diff)

        print(result)
        if args.fail_on_error and result.startswith('❌'):
            exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        exit(1)

if __name__ == '__main__':
    main()
