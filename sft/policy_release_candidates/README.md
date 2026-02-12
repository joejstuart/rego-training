# Policy Release Candidate Rules

These rules are training candidates derived from `policy/release/*` with:

- only PipelineRun-attestation traversal logic,
- SBOM-focused rules excluded,
- no external library calls (`data.lib.*` or `data.release.lib.*`),
- helper functions implemented inline in each rule file.

Source mapping:

- `attestation_type_candidate.rego` <- `policy/release/attestation_type/attestation_type.rego`
- `external_parameters_candidate.rego` <- `policy/release/external_parameters/external_parameters.rego`
- `prefetch_dependencies_candidate.rego` <- `policy/release/prefetch_dependencies/prefetch_dependencies.rego`
- `provenance_materials_candidate.rego` <- `policy/release/provenance_materials/provenance_materials.rego`
- `git_branch_candidate.rego` <- `policy/release/git_branch/git_branch.rego`
- `hermetic_task_candidate.rego` <- `policy/release/hermetic_task/hermetic_task.rego`

Tests:

- Every candidate rule has a matching `_test.rego` file in this directory.

Standalone helper training data:

- `helper_methods/is_pipelinerun_attestation_helper.rego`
- `helper_methods/maybe_tasks_helper.rego`
- `helper_methods/slsa_task_helper.rego`
- `helper_methods/task_param_helper.rego`
- `helper_methods/task_names_helper.rego`
- `helper_methods/normalize_git_url_helper.rego`

Each helper has its own `_test.rego` so helper authoring can be learned independently.
