package build_timestamps_chronological

import rego.v1

deny contains msg if {
	started := time.parse_rfc3339_ns(input.predicate.metadata.buildStartedOn)
	finished := time.parse_rfc3339_ns(input.predicate.metadata.buildFinishedOn)
	started > finished
	msg := "buildStartedOn is after buildFinishedOn"
}
