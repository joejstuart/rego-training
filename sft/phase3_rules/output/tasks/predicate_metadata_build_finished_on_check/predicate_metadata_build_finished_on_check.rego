package predicate_metadata_build_finished_on_check

import rego.v1

deny contains msg if {
	not input.predicate.metadata.buildFinishedOn
	msg := "buildFinishedOn is missing"
}

