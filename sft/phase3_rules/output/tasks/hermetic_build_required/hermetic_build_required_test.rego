package hermetic_build_required_test

import rego.v1

import data.hermetic_build_required

# Instruction: Write a Rego deny rule that rejects the attestation if the build was not performed hermetically. Check that `.predicate.invocation.parameters.hermetic` is `"true"`. Additionally, verify that build-container tasks also have their individual `HERMETIC` parameter set to `"true"`.

# Positive test: valid input should produce no deny violations.
test_hermetic_build_required_valid if {
	count(hermetic_build_required.deny) == 0
	with input as {
		"predicate": {
			"invocation": {
				"parameters": {
					"hermetic": "true",
				},
			},
			"buildConfig": {
				"tasks": [
					{
						"name": "build-container-amd64",
						"invocation": {
							"parameters": {
								"HERMETIC": "true",
							},
						},
					},
					{
						"name": "build-container-arm64",
						"invocation": {
							"parameters": {
								"HERMETIC": "true",
							},
						},
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_hermetic_build_required_invalid if {
	count(hermetic_build_required.deny) > 0
	with input as {
		"predicate": {
			"invocation": {
				"parameters": {
					"hermetic": "true",
				},
			},
			"buildConfig": {
				"tasks": [
					{
						"name": "build-container-amd64",
						"invocation": {
							"parameters": {
								"HERMETIC": "true",
							},
						},
					},
					{
						"name": "build-container-arm64",
						"invocation": {
							"parameters": {
								"HERMETIC": "false",
							},
						},
					},
				],
			},
		},
	}
}
