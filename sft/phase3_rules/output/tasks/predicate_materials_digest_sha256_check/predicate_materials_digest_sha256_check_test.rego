package predicate_materials_digest_sha256_check_test

import rego.v1

import data.predicate_materials_digest_sha256_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.materials[*].digest.sha256` is missing or does not match the expected sha256 digest format. (Predicate field: materials[*].digest.sha256)

# Positive test: valid input should produce no deny violations.
test_predicate_materials_digest_sha256_check_valid if {
	count(predicate_materials_digest_sha256_check.deny) == 0
	with input as {
		"predicate": {
			"materials": [
				{
					"digest": {
						"sha256": "75c6ac42431e29465eba3ff3367a18416722cdc18cb7c5745b448f199082fdef",
					},
				},
			],
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_predicate_materials_digest_sha256_check_invalid if {
	count(predicate_materials_digest_sha256_check.deny) > 0
	with input as {
		"predicate": {
			"materials": [
				{
					"digest": {},
				},
			],
		},
	}
}
