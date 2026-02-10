package type_check

import rego.v1

deny contains msg if {
	input._type != "https://in-toto.io/Statement/v0.1"
	msg := sprintf("_type is %v, expected https://in-toto.io/Statement/v0.1", [input._type])
}

