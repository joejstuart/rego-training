package task_service_account_name_check

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	task.serviceAccountName != "appstudio-pipeline"
	msg := sprintf("serviceAccountName is %v, expected appstudio-pipeline", [task.serviceAccountName])
}

