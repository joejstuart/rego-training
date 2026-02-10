package subject_digest_sha256_check_test

import rego.v1

import data.subject_digest_sha256_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.subject[*].digest.sha256` is missing or does not match the expected sha256 digest format. (Field: subject[*].digest.sha256)

# Positive test: valid input should produce no deny violations.
test_subject_digest_sha256_check_valid if {
	count(subject_digest_sha256_check.deny) == 0
	with input as {
		"subject": [
			{
				"digest": {
					"sha256": "51699c948c8b81da515421baa8adc3a3f061c0af2a13a0933176469464772f16",
				},
			},
		],
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_subject_digest_sha256_check_invalid if {
	count(subject_digest_sha256_check.deny) > 0
	with input as {
		"subject": [
			{
				"digest": {},
			},
		],
	}
}
