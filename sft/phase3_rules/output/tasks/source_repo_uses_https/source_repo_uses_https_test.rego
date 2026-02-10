package source_repo_uses_https_test

import rego.v1

import data.source_repo_uses_https

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.invocation.parameters["git-url"]` does not start with `"https://"`. Builds from non-HTTPS sources are not allowed.

# Positive test: valid input should produce no deny violations.
test_source_repo_uses_https_valid if {
	count(source_repo_uses_https.deny) == 0
	with input as {
		"predicate": {
			"invocation": {
				"parameters": {
					"git-url": "https://github.com/example/repo",
				},
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_source_repo_uses_https_invalid if {
	count(source_repo_uses_https.deny) > 0
	with input as {
		"predicate": {
			"invocation": {
				"parameters": {
					"git-url": "http://github.com/example/repo",
				},
			},
		},
	}
}
