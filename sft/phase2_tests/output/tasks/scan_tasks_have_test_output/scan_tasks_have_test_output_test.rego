package scan_tasks_have_test_output_test

import rego.v1

import data.scan_tasks_have_test_output

# Instruction: Write a Rego deny rule that rejects the attestation if any task whose name contains `"scan"` or `"sast"` does not have a result named `"TEST_OUTPUT"`. Security scan tasks must produce test output.

# Positive test: valid input should produce no deny violations.
test_scan_tasks_have_test_output_valid if {
	count(scan_tasks_have_test_output.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "clair-scan",
						"status": "Succeeded",
						"results": [
							{
								"name": "TEST_OUTPUT",
								"type": "string",
								"value": "{}",
							},
							{
								"name": "SCAN_OUTPUT",
								"type": "string",
								"value": "{}",
							},
						],
					},
					{
						"name": "sast-snyk-check",
						"status": "Succeeded",
						"results": [
							{
								"name": "REPORTS",
								"type": "string",
								"value": "{}",
							},
							{
								"name": "TEST_OUTPUT",
								"type": "string",
								"value": "{}",
							},
						],
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_scan_tasks_have_test_output_invalid if {
	count(scan_tasks_have_test_output.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "clair-scan",
						"status": "Succeeded",
						"results": [
							{
								"name": "TEST_OUTPUT",
								"type": "string",
								"value": "{}",
							},
							{
								"name": "SCAN_OUTPUT",
								"type": "string",
								"value": "{}",
							},
						],
					},
					{
						"name": "sast-snyk-check",
						"status": "Succeeded",
						"results": [
							{
								"name": "REPORTS",
								"type": "string",
								"value": "{}",
							},
						],
					},
				],
			},
		},
	}
}
