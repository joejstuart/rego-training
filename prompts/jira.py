from langchain.prompts import PromptTemplate

FULL_WEEKLY_SUMMARY = PromptTemplate(
    template="""
You are a seasoned project manager composing the weekly status update.

Here are this week's Jira issues, separated by status:
{jira_blob}

Your task: Write a concise narrative summary that MUST follow this exact structure:
The tone should be casual and conversational.

1. Start with a brief overview paragraph that captures the main themes of the week's work. This paragraph should be concise and to the point.
2. Follow with two main sections:
   a. Completed Work: Summarize the finished work
   b. Work In Progress: Summarize the ongoing work
3. For each section:
   - Use past tense for completed work
   - Use present/future tense for ongoing work
   - Include the impact or benefit
   - Omit issue numbers unless specifically relevant
   - Focus on telling a cohesive story about the work done
4. Then a conclusion that summarizes the work in each section.

Example format:
    This week, the team made significant progress in infrastructure improvements and team onboarding. We streamlined our development processes and enhanced our tooling capabilities while making steady progress on ongoing initiatives.

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

    Overall, the team made significant progress in infrastructure improvements and team onboarding. We streamlined our development processes and enhanced our tooling capabilities while making steady progress on ongoing initiatives.

Now, based on the descriptions above, write your summary following this EXACT structure:
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
2. Completed Work: summarize finished work in past tense with impact/benefit.
3. Conclusion.

Omit issue numbers and don’t hallucinate—cover only items in “## Completed Work.”
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
2. Work In Progress: summarize ongoing work in present/future tense with impact/benefit.
3. Conclusion.

Omit issue numbers and don’t hallucinate—cover only items in “## Work In Progress.”
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

Summary: <Imperative, “As a …” phrasing optional>

Acceptance Criteria:
- <Given…When…Then…> or “The system must…” statement  
- …  
- …

Tip:
- Use active voice (“The user can…”).  
- Prefer Given/When/Then for behavior-driven clarity:  
  • Given X, when Y, then Z.

Example:

Raw details: I’m a customer and I can’t find products by name when I search.

Output:
Summary: As a customer, I want to search for products by name.

Acceptance Criteria:
- Given a valid name, when I search, then matching products appear.  
- The system must return partial matches with at least three matching characters.  
- Search results must show name, image, and price. 
""",
    input_variables=["jira_blob"],
)
