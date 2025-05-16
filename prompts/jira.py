from langchain.prompts import PromptTemplate

SPRINT_SUMMARY_PROMPT = PromptTemplate(
    template="""
You are a seasoned project manager composing the sprint status update.

Here are this sprint's issues, grouped by status:
{jira_blob}

Your task: Write a concise narrative summary that MUST follow this exact structure:
The tone should be casual and conversational.

1. Start with a brief overview paragraph that captures the main themes of the week's work. This paragraph should be concise and to the point.
2. If there are any Critical, Blocker, or Major priority issues, include a "High Priority Items" section immediately after the overview.
3. Follow with three main sections:
   a. Completed Work: Group related completed items into themes and summarize their impact
   b. Work In Progress: Group related ongoing work into themes and summarize their progress
   c. New: Group related new items into themes and summarize their purpose
4. For each section:
   - Group related items into 2-3 key themes
   - Use past tense for completed work
   - Use present/future tense for ongoing work
   - Focus on the overall impact and purpose of each theme
   - Omit individual issue numbers unless specifically relevant
   - Provide a high-level summary of each theme rather than listing individual items
   - ALWAYS include issue numbers for Critical, Blocker, or Major priority items
5. Then a conclusion that summarizes the work in each section.

Example format:
    This sprint, we focused on hardening our release pipeline and kicking off the VSA feature. We completed core CI/CD improvements, made good progress on service integration, and still have a few backlog items to tackle.

    High Priority Items:
        - [PROJ-123] Critical security vulnerability in release pipeline - Currently being addressed
        - [PROJ-456] Blocker issue with VSA generation - Blocked by external dependency

    Completed Work:
        Our infrastructure improvements focused on release management and deployment flexibility. We decommissioned the v0.4 branch and its associated releases, which streamlined our release process. Additionally, we updated the allowed registry prefixes in konflux-release-data, enabling more flexible deployments. These changes have made our release process more efficient and adaptable.

        The team also completed several tooling enhancements:
        • Rolled out the new Sealights browser plugin and verified its functionality
        • Enabled auto-merge for Renovate/Dependabot updates to improve dependency management

    Work In Progress:
        We are currently focused on implementing the VSA (Verification Summary Attestation) feature. This work includes:
        • Developing the core functionality for generating VSAs
        • Investigating storage options in Rekor
        • Creating configuration parameters for VSA generation

    New:
        We have two main areas of new work planned:
        1. Policy and Compliance Enhancements: Several new policy checks and compliance features are planned, including hermetic pre-build script verification and policy compliance for in-git script tasks.
        2. Infrastructure Modernization: We're planning to upgrade our Go version and replace Cosign with Sigstore in our CLI tools, which will improve our security posture and maintainability.

    Overall, the team shipped critical release enhancements, advanced the VSA groundwork, and has clear next steps to finish the sprint.

Now, based on the blob above, write your sprint summary following that structure. Remember to:
1. Group related items into themes and provide high-level summaries rather than listing individual issues
2. ALWAYS include a "High Priority Items" section if there are any Critical, Blocker, or Major priority issues
3. For high priority issues, include their issue numbers and explain their impact
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

Structure you should follow:
    The EC team had a productive week. We completed several infrastructure improvements and tooling enhancements and have key items in progress.

    High Priority Items:
        [ALWAYS include this section if there are any Critical, Blocker, or Major priority issues]
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
