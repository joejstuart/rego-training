package predicate_invocation_parameters_output_image_check

import rego.v1

deny contains msg if {
	not input.predicate.invocation.parameters["output-image"]
	msg := "output-image is missing"
}

