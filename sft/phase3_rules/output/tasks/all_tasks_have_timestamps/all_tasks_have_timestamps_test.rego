package all_tasks_have_timestamps_test

import rego.v1

import data.all_tasks_have_timestamps

# Instruction: Write a Rego deny rule that rejects the attestation if any task in `.predicate.buildConfig.tasks` is missing either `startedOn` or `finishedOn` timestamps.

# Positive test: valid input should produce no deny violations.
test_all_tasks_have_timestamps_valid if {
	count(all_tasks_have_timestamps.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "build",
						"startedOn": "2025-05-12T12:09:57Z",
						"finishedOn": "2025-05-12T12:10:03Z",
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_all_tasks_have_timestamps_invalid if {
	count(all_tasks_have_timestamps.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "build",
						"startedOn": "2025-05-12T12:09:57Z",
						"finishedOn": "2025-05-12T12:10:03Z",
					},
					{
						"name": "test",
						"startedOn": "2025-05-12T12:10:04Z",
					},
				],
			},
		},
	}
}
