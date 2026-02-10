package predicate_metadata_build_started_on_check

import rego.v1

deny contains msg if {
	not input.predicate.metadata.buildStartedOn
	msg := "buildStartedOn is missing"
}

