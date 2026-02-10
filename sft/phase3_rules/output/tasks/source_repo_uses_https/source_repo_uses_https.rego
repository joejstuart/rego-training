package source_repo_uses_https

import rego.v1

deny contains msg if {
	url := input.predicate.invocation.parameters["git-url"]
	not startswith(url, "https://")
	msg := sprintf("git-url %v does not use HTTPS", [url])
}
