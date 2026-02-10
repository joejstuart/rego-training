package all_subjects_have_digest_test

import rego.v1

import data.all_subjects_have_digest

# Instruction: Write a Rego deny rule that rejects the attestation if any subject in `.subject` is missing a `digest.sha256` field.

# Positive test: valid input should produce no deny violations.
test_all_subjects_have_digest_valid if {
	count(all_subjects_have_digest.deny) == 0
	with input as {
		"subject": [
			{
				"name": "image1",
				"digest": {
					"sha256": "abc123def456",
				},
			},
		],
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_all_subjects_have_digest_invalid if {
	count(all_subjects_have_digest.deny) > 0
	with input as {
		"subject": [
			{
				"name": "image1",
				"digest": {
					"sha256": "abc123def456",
				},
			},
			{
				"name": "image2",
			},
		],
	}
}
