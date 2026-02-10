package predicate_materials_uri_check

import rego.v1

deny contains msg if {
	some material in input.predicate.materials
	material.uri != "oci://registry.access.redhat.com/ubi9/skopeo"
	msg := sprintf("uri is %v, expected oci://registry.access.redhat.com/ubi9/skopeo", [material.uri])
}

