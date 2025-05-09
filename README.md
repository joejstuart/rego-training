# AIAgent

A simple setup for running an AI agent using a specified model API and SSL certificate.

## Getting Started

Follow these steps to configure and run the agent.

---

### Models corp documentation

https://gitlab.cee.redhat.com/models-corp/user-documentation


### 1. Set Up Environment Variables

Create a `.env` file in the project root and add the following:

```env
MODEL_API="https://granite-3-2-8b-instruct--apicast-production.apps.int.stc.ai.prod.us-east-1.aws.paas.redhat.com:443/v1"
MODEL_ID="/data/granite-3.2-8b-instruct"
USER_KEY="YOUR-USER_KEY"

JIRA_URL="https://issues.redhat.com"
JIRA_API_TOKEN="YOUR JIRA PAT"
```

#### SSL Cert

```bash
echo | openssl s_client -connect granite-3-2-8b-instruct--apicast-production.apps.int.stc.ai.prod.us-east-1.aws.paas.redhat.com:443 | openssl x509 > /tmp/granite-3-2-8b.crt
export SSL_CERT_FILE=/tmp/granite-3-2-8b.crt
```

#### Running the agent

```bash
uv run main.py
```

#### Example Jira search

The `jira_search` tells the model to use the `search_jira` function.

```
jira-search project = EC AND assignee = jjstuart-rh AND status = 'In Progress'
```

#### Summarize Jira issues

```
jira-summarize project = EC AND assignee = jjstuart-rh AND status = 'In Progress'
```
