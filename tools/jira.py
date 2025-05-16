import os
import logging
from dotenv import load_dotenv
from jira import JIRA

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ─── load .env ───────────────────────────────────────────────────────────────
load_dotenv()

JIRA_URL       = os.getenv("JIRA_URL")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")

if not all([JIRA_URL, JIRA_API_TOKEN]):
    raise RuntimeError("Missing JIRA_URL or JIRA_API_TOKEN in .env")

# ─── create a Jira client ─────────────────────────────────────────────────────
jira_client = JIRA(server=JIRA_URL, token_auth=JIRA_API_TOKEN)

# Example JQL queries for common use cases
EXAMPLE_JQL_QUERIES = {
    "weekly_status": """
project = EC
AND issuetype IN (Bug, Epic, Feature, Story, Task)
AND (
    status = "In Progress"
OR (status = Closed AND resolved >= -1w)
)
"""
}

def get_jql_help() -> str:
    """
    Returns a help message with example JQL queries and their descriptions.
    """
    help_text = """Common JQL Query Examples:

1. Weekly Status Update:
   project = EC
    AND issuetype IN (Bug, Epic, Feature, Story, Task)
    AND (
        status = "In Progress"
    OR (status = Closed AND resolved >= -1w)
    )

2. Open Issues:
   project = EC AND status = Open

3. Issues Assigned to Me:
   project = EC AND assignee = currentUser()

4. Issues in Current Sprint:
   project = EC AND sprint in openSprints()

5. High Priority Issues:
   project = EC AND priority = High

JQL Tips:
- Use AND, OR, NOT for combining conditions
- Use IN for multiple values: status IN (Open, 'In Progress')
- Use = for exact matches
- Use ~ for contains: summary ~ "search term"
- Use >=, <=, >, < for dates: created >= -7d
- Use currentUser() for the current user
- Use openSprints() for current sprint
"""
    return help_text

def search_jira(jql: str, max_results: int = 50, use_example: str = None) -> str:
    """
    Search Jira for issues matching the given JQL query.
    Returns a newline-separated summary of issue keys + titles.
    
    Args:
        jql: The JQL query string
        max_results: Maximum number of results to return
        use_example: Optional key from EXAMPLE_JQL_QUERIES to use instead of jql
    """
    if jql.lower() == "help":
        return get_jql_help()
        
    if use_example and use_example in EXAMPLE_JQL_QUERIES:
        jql = EXAMPLE_JQL_QUERIES[use_example]
    
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

def fetch_jira_descriptions(jql: str, max_results: int = 50) -> str:
    """
    Search Jira and return a markdown blob of key + description for each issue,
    separated by status (Closed vs In Progress).
    """
    # Reuse search_jira's JQL handling
    if jql.lower() == "help":
        return get_jql_help()
    
    issues = jira_client.search_issues(jql, maxResults=max_results)
    
    if not issues:
        return "No issues found."

    # Separate issues by status
    closed_issues = []
    in_progress_issues = []
    new_issues = []
    
    for iss in issues:
        desc = iss.fields.description or "_No description provided._"
        priority = iss.fields.priority.name if hasattr(iss.fields, 'priority') else "No Priority"
        issue_text = f"### {iss.key} (Priority: {priority})\n\n{desc.strip()}"
        
        # Add comments if they exist
        comments = iss.fields.comment.comments
        if comments:
            issue_text += "\n\n#### Comments:\n"
            for comment in comments:
                author = comment.author.displayName
                created = comment.created.split('T')[0]  # Get just the date part
                issue_text += f"\n**{author}** ({created}):\n{comment.body}\n"
        
        if iss.fields.status.name == "Closed":
            closed_issues.append(issue_text)
        elif iss.fields.status.name == "New":
            new_issues.append(issue_text)
        else:
            in_progress_issues.append(issue_text)
    
    # Build the result with clear section headers
    result = []
    
    if closed_issues:
        result.append("## Completed Work\n")
        result.extend(closed_issues)
    
    if in_progress_issues:
        if result:  # Add separator if we have both sections
            result.append("\n---\n")
        result.append("## Work In Progress\n")
        result.extend(in_progress_issues)

    if new_issues:
        if result:  # Add separator if we have both sections
            result.append("\n---\n")
        result.append("## New\n")
        result.extend(new_issues)
    
    return "\n\n".join(result)
