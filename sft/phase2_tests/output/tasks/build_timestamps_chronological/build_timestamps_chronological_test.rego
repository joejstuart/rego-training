package build_timestamps_chronological_test

import rego.v1

import data.build_timestamps_chronological

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.metadata.buildStartedOn` is after `.predicate.metadata.buildFinishedOn`. The build start time must be earlier than or equal to the build finish time.

# Positive test: valid input should produce no deny violations.
test_build_timestamps_chronological_valid if {
	count(build_timestamps_chronological.deny) == 0
	with input as {
		"predicate": {
			"metadata": {
				"buildStartedOn": "2025-05-12T12:09:47Z",
				"buildFinishedOn": "2025-05-12T12:20:00Z",
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_build_timestamps_chronological_invalid if {
	count(build_timestamps_chronological.deny) > 0
	with input as {
		"predicate": {
			"metadata": {
				"buildStartedOn": "2025-05-12T12:20:00Z",
				"buildFinishedOn": "2025-05-12T12:09:47Z",
			},
		},
	}
}
