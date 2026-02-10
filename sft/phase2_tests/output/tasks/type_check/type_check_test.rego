package type_check_test

import rego.v1

import data.type_check

# Instruction: Write a Rego deny rule that rejects the attestation if `._type` is not `"https://in-toto.io/Statement/v0.1"`. (In-toto statement type URI)

# Positive test: valid input should produce no deny violations.
test_type_check_valid if {
	count(type_check.deny) == 0
	with input as {
		"_type": "https://in-toto.io/Statement/v0.1",
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_type_check_invalid if {
	count(type_check.deny) > 0
	with input as {
		"_type": "https://example.com/INVALID",
	}
}
