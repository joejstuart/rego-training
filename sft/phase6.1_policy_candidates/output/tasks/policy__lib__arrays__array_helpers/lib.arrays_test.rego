package phase6_policy_lib_smoke_test

import rego.v1

import data.lib.arrays as target

test_module_loads if {
	_ := target
}
