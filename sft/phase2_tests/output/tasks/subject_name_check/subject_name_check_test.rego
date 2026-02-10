package subject_name_check_test

import rego.v1

import data.subject_name_check

# Instruction: Write a Rego deny rule that rejects the attestation if the field `.subject[*].name` is missing. (Field: subject[*].name)

# Positive test: valid input should produce no deny violations.
test_subject_name_check_valid if {
	count(subject_name_check.deny) == 0
	with input as {
		"subject": [
			{
				"name": "quay.io/redhat-user-workloads/rhtap-contract-tenant/golden-container/golden-container",
			},
		],
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_subject_name_check_invalid if {
	count(subject_name_check.deny) > 0
	with input as {
		"subject": [
			{},
		],
	}
}
