package predicate_invocation_parameters_git_url_check_test

import rego.v1

import data.predicate_invocation_parameters_git_url_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.invocation.parameters.git-url` is not `"https://github.com/enterprise-contract/golden-container"`. (Predicate field: invocation.parameters.git-url)

# Positive test: valid input should produce no deny violations.
test_predicate_invocation_parameters_git_url_check_valid if {
	count(predicate_invocation_parameters_git_url_check.deny) == 0
	with input as {
		"predicate": {
			"invocation": {
				"parameters": {
					"git-url": "https://github.com/enterprise-contract/golden-container",
				},
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_predicate_invocation_parameters_git_url_check_invalid if {
	count(predicate_invocation_parameters_git_url_check.deny) > 0
	with input as {
		"predicate": {
			"invocation": {
				"parameters": {
					"git-url": "https://example.com/INVALID",
				},
			},
		},
	}
}
