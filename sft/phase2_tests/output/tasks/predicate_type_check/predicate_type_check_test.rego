package predicate_type_check_test

import rego.v1

import data.predicate_type_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicateType` is not `"https://slsa.dev/provenance/v0.2"`. (SLSA predicate type URI)

# Positive test: valid input should produce no deny violations.
test_predicate_type_check_valid if {
	count(predicate_type_check.deny) == 0
	with input as {
		"predicateType": "https://slsa.dev/provenance/v0.2",
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_predicate_type_check_invalid if {
	count(predicate_type_check.deny) > 0
	with input as {
		"predicateType": "https://example.com/INVALID",
	}
}
