package all_materials_have_digest_test

import rego.v1

import data.all_materials_have_digest

# Instruction: Write a Rego deny rule that rejects the attestation if any material in `.predicate.materials` is missing a `digest` field with at least a `sha256` or `sha1` entry.

# Positive test: valid input should produce no deny violations.
test_all_materials_have_digest_valid if {
	count(all_materials_have_digest.deny) == 0
	with input as {
		"predicate": {
			"materials": [
				{
					"uri": "oci://quay.io/example/image",
					"digest": {
						"sha256": "abc123",
					},
				},
			],
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_all_materials_have_digest_invalid if {
	count(all_materials_have_digest.deny) > 0
	with input as {
		"predicate": {
			"materials": [
				{
					"uri": "oci://quay.io/example/image",
					"digest": {
						"sha256": "abc123",
					},
				},
				{
					"uri": "oci://quay.io/example/other",
				},
			],
		},
	}
}
