package predicate_materials_check_test

import rego.v1

import data.predicate_materials_check

# Instruction: Write a Rego deny rule that rejects the attestation if the field `.predicate.materials` is missing or empty. (Predicate field: materials)

# Positive test: valid input should produce no deny violations.
test_predicate_materials_check_valid if {
	count(predicate_materials_check.deny) == 0
	with input as {
		"predicate": {
			"materials": "example-value",
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_predicate_materials_check_invalid if {
	count(predicate_materials_check.deny) > 0
	with input as {
		"predicate": {},
	}
}
