package predicate_invocation_parameters_git_url_check

import rego.v1

deny contains msg if {
	input.predicate.invocation.parameters["git-url"] != "https://github.com/enterprise-contract/golden-container"
	msg := sprintf("git-url is %v, expected https://github.com/enterprise-contract/golden-container", [input.predicate.invocation.parameters["git-url"]])
}

