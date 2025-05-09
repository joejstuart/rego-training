import os
from dotenv import load_dotenv
from jira import JIRA

# ─── load .env ───────────────────────────────────────────────────────────────
load_dotenv()

JIRA_URL       = os.getenv("JIRA_URL")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")

# ─── create a Jira client ─────────────────────────────────────────────────────
jira_client = JIRA(server=JIRA_URL, token_auth=JIRA_API_TOKEN)

def search_jira(jql: str) -> str:
    """
    Search Jira for issues matching the given JQL query.
    Returns a newline‑separated summary of issue keys + titles.
    """
    issues = jira_client.search_issues(jql, maxResults=10)
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
