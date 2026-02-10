package predicate_materials_uri_check_test

import rego.v1

import data.predicate_materials_uri_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.materials[*].uri` is not `"oci://registry.access.redhat.com/ubi9/skopeo"`. (Predicate field: materials[*].uri)

# Positive test: valid input should produce no deny violations.
test_predicate_materials_uri_check_valid if {
	count(predicate_materials_uri_check.deny) == 0
	with input as {
		"predicate": {
			"materials": [
				{
					"uri": "oci://registry.access.redhat.com/ubi9/skopeo",
				},
			],
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_predicate_materials_uri_check_invalid if {
	count(predicate_materials_uri_check.deny) > 0
	with input as {
		"predicate": {
			"materials": [
				{
					"uri": "oci://example.com/INVALID",
				},
			],
		},
	}
}
