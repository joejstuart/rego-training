from langchain.prompts import PromptTemplate

SPRINT_SUMMARY_PROMPT = PromptTemplate(
    template="""
You are a seasoned project manager composing a status update for the current sprint.

Here are this week's Jira issues, separated by status:
{jira_blob}

Your task: Write a concise narrative summary of all the issues above. Follow the guidelines below.

Guidelines:
    - Use past tense for completed work
    - Use present/future tense for ongoing work
    - Focus on the overall impact and purpose of each theme
    - Omit individual issue numbers unless specifically relevant
    - Provide a high-level summary of each theme rather than listing individual items
    - ALWAYS highlight any issues marked as Critical, Blocker, or Major priority
    - If there are no issues marked as Critical, Blocker, or Major priority, say so.
""",
    input_variables=["jira_blob"],
)

FULL_WEEKLY_SUMMARY = PromptTemplate(
    template="""
You are a seasoned project manager composing the weekly status update.

Here are this week's Jira issues, separated by status:
{jira_blob}

Your task: Write a concise narrative summary that MUST follow the guidelines and the exact structure below:

Guidelines:
    - Use past tense for completed work
    - Use present/future tense for ongoing work
    - Focus on the overall impact and purpose of each theme
    - Omit individual issue numbers unless specifically relevant
    - Provide a high-level summary of each theme rather than listing individual items
    - ALWAYS highlight any issues marked as Critical, Blocker, or Major priority
    - For high priority issues, include their issue numbers and explain their impact
    - Do not use asterisks (*) for formatting - use plain text only

Structure you should follow:
    The EC team had a productive week. We completed several infrastructure improvements and tooling enhancements and have key items in progress.

    High Priority Items:
        - [ALWAYS include this section if there are any Critical, Blocker, or Major priority issues]
        - [List and explain any high priority issues, including their impact and current status]

    Completed Work:
        Our infrastructure improvements focused on release management and deployment flexibility:
        - We decommissioned the v0.4 branch and its associated releases, which streamlined our release process. 
        - Additionally, we updated the allowed registry prefixes in konflux-release-data, enabling more flexible deployments.

        The team also completed several tooling enhancements:
        - Rolled out the new Sealights browser plugin and verified its functionality
        - Enabled auto-merge for Renovate/Dependabot updates to improve dependency management

    Work In Progress:
        We are currently focused on implementing the VSA (Verification Summary Attestation) feature. This work includes:
        - Developing the core functionality for generating VSAs
        - Investigating storage options in Rekor
        - Creating configuration parameters for VSA generation

    Overall, the team made significant progress in infrastructure improvements and team onboarding. We streamlined our development processes and enhanced our tooling capabilities while making steady progress on ongoing initiatives.

Now, based on the descriptions above, write your summary following this EXACT structure. Remember to:
1. Group related items into themes and provide high-level summaries rather than listing individual issues
2. ALWAYS include a "High Priority Items" section if there are any Critical, Blocker, or Major priority issues
3. For high priority issues, include their issue numbers and explain their impact
4. Use plain text without any asterisks or markdown formatting
""",
    input_variables=["jira_blob"],
)

COMPLETED_ONLY_SUMMARY = PromptTemplate(
    template="""
You are a seasoned project manager composing the weekly status update.

Here are this week's Jira issues (## Completed Work only):
{jira_blob}

Your task: Write a concise narrative summary that follows this structure:
1. Overview paragraph (concise themes).
2. Completed Work: Group related completed items into 2-3 key themes and summarize their impact. Focus on the overall impact and purpose of each theme rather than listing individual items.
3. Conclusion.

Omit issue numbers and don't hallucinate—cover only items in "## Completed Work."
""",
    input_variables=["jira_blob"],
)

WIP_ONLY_SUMMARY = PromptTemplate(
    template="""
You are a seasoned project manager composing the weekly status update.

Here are this week's Jira issues (## Work In Progress only):
{jira_blob}

Your task: Write a concise narrative summary that follows this structure:
1. Overview paragraph (concise themes).
2. Work In Progress: Group related ongoing items into 2-3 key themes and summarize their progress. Focus on the overall impact and purpose of each theme rather than listing individual items.
3. Conclusion.

Omit issue numbers and don't hallucinate—cover only items in "## Work In Progress."
""",
    input_variables=["jira_blob"],
)

ACCEPTANCE_CRITERIA_PROMPT = PromptTemplate(
    template="""
You are an expert Jira issue writer.  
Acronyms:  
- EC = Enterprise Contract  
- VSA = Verification Summary Attestation  

Raw details: {jira_blob}  

Task:
1. Write a one-line, imperative Summary.  
2. Generate 3-5 concise Acceptance Criteria that each:  
   • Describe a single, testable outcome  
   • Are phrased from at least two perspectives (user/developer)  
   • Are unique—if any two criteria overlap in meaning, include only one  

Consider Perspectives:
- **End user**: clarity and error feedback  
- **Developer**: API contract and performance  

Format exactly as follows (no extra sections):

Summary: <Imperative, "As a …" phrasing optional>

Acceptance Criteria:
- <Given…When…Then…> or "The system must…" statement  
- …  
- …

Tip:
- Use active voice ("The user can…").  
- Prefer Given/When/Then for behavior-driven clarity:  
  • Given X, when Y, then Z.

Example:

Raw details: I'm a customer and I can't find products by name when I search.

Output:
Summary: As a customer, I want to search for products by name.

Acceptance Criteria:
- Given a valid name, when I search, then matching products appear.  
- The system must return partial matches with at least three matching characters.  
- Search results must show name, image, and price. 
""",
    input_variables=["jira_blob"],
)
