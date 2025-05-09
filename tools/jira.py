import os
from dotenv import load_dotenv
from jira import JIRA

# ─── load .env ───────────────────────────────────────────────────────────────
load_dotenv()

JIRA_URL       = os.getenv("JIRA_URL")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")

if not all([JIRA_URL, JIRA_API_TOKEN]):
    raise RuntimeError("Missing JIRA_URL or JIRA_API_TOKEN in .env")

# ─── create a Jira client ─────────────────────────────────────────────────────
jira_client = JIRA(server=JIRA_URL, token_auth=JIRA_API_TOKEN)

def search_jira(jql: str, max_results: int = 50) -> str:
    """
    Search Jira for issues matching the given JQL query.
    Returns a newline-separated summary of issue keys + titles.
    """
    issues = jira_client.search_issues(jql, maxResults=max_results)
    if not issues:
        return "No issues found."
    lines = [f"{iss.key}: {iss.fields.summary}" for iss in issues]
    return "\n".join(lines)

def create_jira_issue(project_key: str, summary: str, description: str) -> str:
    """
    Create a new Jira issue and return its key and URL.
    """
    issue_dict = {
        "project": {"key": project_key},
        "summary": summary,
        "description": description,
        "issuetype": {"name": "Task"},
    }
    new_issue = jira_client.create_issue(fields=issue_dict)
    url = f"{JIRA_URL}/browse/{new_issue.key}"
    return f"Issue {new_issue.key} created: {url}"

def fetch_jira_descriptions(jql: str, max_results: int = 20) -> str:
    """
    Search Jira and return a markdown blob of key + description for each issue.
    """
    issues = jira_client.search_issues(jql, maxResults=max_results)
    if not issues:
        return "No issues found."
    parts = []
    for iss in issues:
        desc = iss.fields.description or "_No description provided._"
        parts.append(f"### {iss.key}\n\n{desc.strip()}")
    return "\n\n---\n\n".join(parts)
