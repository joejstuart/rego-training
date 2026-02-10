package all_subjects_have_name_test

import rego.v1

import data.all_subjects_have_name

# Instruction: Write a Rego deny rule that rejects the attestation if any subject in `.subject` is missing the `name` field.

# Positive test: valid input should produce no deny violations.
test_all_subjects_have_name_valid if {
	count(all_subjects_have_name.deny) == 0
	with input as {
		"subject": [
			{
				"name": "quay.io/example/image",
				"digest": {
					"sha256": "abc123",
				},
			},
		],
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_all_subjects_have_name_invalid if {
	count(all_subjects_have_name.deny) > 0
	with input as {
		"subject": [
			{
				"name": "quay.io/example/image",
				"digest": {
					"sha256": "abc123",
				},
			},
			{
				"digest": {
					"sha256": "def456",
				},
			},
		],
	}
}
