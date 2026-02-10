package tls_verify_enabled_test

import rego.v1

import data.tls_verify_enabled

# Instruction: Write a Rego deny rule that rejects the attestation if any task in `.predicate.buildConfig.tasks` that has a `TLSVERIFY` invocation parameter set to anything other than `"true"`. Image pushes without TLS verification are a supply chain risk.

# Positive test: valid input should produce no deny violations.
test_tls_verify_enabled_valid if {
	count(tls_verify_enabled.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "build-container-amd64",
						"invocation": {
							"parameters": {
								"TLSVERIFY": "true",
							},
						},
					},
					{
						"name": "build-container-arm64",
						"invocation": {
							"parameters": {
								"TLSVERIFY": "true",
							},
						},
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_tls_verify_enabled_invalid if {
	count(tls_verify_enabled.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "build-container-amd64",
						"invocation": {
							"parameters": {
								"TLSVERIFY": "true",
							},
						},
					},
					{
						"name": "build-container-arm64",
						"invocation": {
							"parameters": {
								"TLSVERIFY": "false",
							},
						},
					},
				],
			},
		},
	}
}
