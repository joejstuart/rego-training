#!/usr/bin/env python3
"""
Phase 1: Derive Natural Language Instructions from Field Catalog.

Reads the field catalog produced by Phase 0 and generates natural language
instructions at three tiers of complexity.  Each instruction describes what
a Rego deny rule should check, and is paired with metadata that downstream
phases need to generate tests and rules.

Usage:
    cd sft/
    python phase1_instructions/derive_instructions.py
    python phase1_instructions/derive_instructions.py --catalog phase0_catalog/output/field_catalog.jsonl
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _load_catalog(path: str) -> list[dict]:
    """Load the JSONL field catalog into a list of dicts."""
    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def _sanitize_package_name(name: str) -> str:
    """Make a name safe for Rego package names (lowercase, underscores only)."""
    name = re.sub(r"[^a-z0-9_]", "_", name.lower())
    name = re.sub(r"_+", "_", name)
    return name.strip("_")


def _path_to_rego_access(json_path: str) -> str:
    """
    Convert a JSON dot-path to Rego access syntax.

    Examples:
        ._type                              → input._type
        .predicateType                      → input.predicateType
        .predicate.builder.id               → input.predicate.builder.id
        .predicate.buildConfig.tasks[*]     → input.predicate.buildConfig.tasks[_]
    """
    p = json_path.lstrip(".")
    p = p.replace("[*]", "[_]")
    return f"input.{p}"


def _build_mock_from_path(json_path: str, value: Any) -> dict:
    """
    Build a minimal mock data dict from a dotted JSON path and a leaf value.

    Example: path=".predicate.builder.id", value="https://tekton.dev/chains/v2"
    Returns: {"predicate": {"builder": {"id": "https://tekton.dev/chains/v2"}}}
    """
    parts = json_path.lstrip(".").split(".")
    # Remove array wildcards from parts for mock data structure
    clean_parts = [p.replace("[*]", "") for p in parts]

    mock: dict = {}
    current = mock
    for i, part in enumerate(clean_parts):
        if i == len(clean_parts) - 1:
            current[part] = value
        else:
            # Check if the next level in the original path was an array
            original = parts[i]
            if "[*]" in original:
                current[part] = [{}]
                current = current[part][0]
            else:
                current[part] = {}
                current = current[part]
    return mock


# ─── Filters ─────────────────────────────────────────────────────────────────
# Not every catalog entry makes a good training instruction.  We curate which
# entries generate Tier 1 and Tier 2 instructions to avoid low-value noise.

# Fields to SKIP entirely (operational metadata, huge blobs, duplicates)
_SKIP_IDS = {
    # Step entryPoints are massive bash scripts, not policy-relevant
    "task_step_entry_point",
    # Span context / tracing metadata
    "task_invocation_environment_annotations_tekton_dev_taskrun_span_context",
    # Controller info (JSON blob, infra detail)
    "task_invocation_environment_annotations_pipelinesascode_tekton_dev_controller_info",
    "predicate_invocation_environment_annotations_pipelinesascode_tekton_dev_controller_info",
    # Record summary annotations (JSON blob)
    "task_invocation_environment_annotations_results_tekton_dev_record_summary_annotations",
    "predicate_invocation_environment_annotations_results_tekton_dev_record_summary_annotations",
    # Step annotations (always null)
    "task_step_annotations",
}

# For Tier 1, only generate instructions for these "interesting" fields.
# Avoids generating 200+ trivial instructions for every annotation/label.
_TIER1_TOP_LEVEL_IDS = {
    "type",
    "predicate_type",
    "subject_name",
    "subject_digest_sha256",
}

_TIER1_PREDICATE_IDS = {
    "predicate_build_type",
    "predicate_builder_id",
    "predicate_metadata_build_started_on",
    "predicate_metadata_build_finished_on",
    "predicate_metadata_reproducible",
    "predicate_materials",
    "predicate_materials_uri",
    "predicate_materials_digest_sha256",
    "predicate_invocation_parameters_git_url",
    "predicate_invocation_parameters_output_image",
    "predicate_invocation_parameters_hermetic",
    "predicate_invocation_parameters_revision",
    "predicate_invocation_parameters_rebuild",
    "predicate_invocation_parameters_skip_checks",
}

_TIER1_TASK_IDS = {
    "task_name",
    "task_status",
    "task_started_on",
    "task_finished_on",
    "task_service_account_name",
    "task_ref_resolver",
    "task_ref_params_name",
    "task_ref_params_value",
    "task_invocation_parameters_hermetic",
    "task_invocation_parameters_image",
    "task_invocation_parameters_dockerfile",
    "task_invocation_parameters_commit_sha",
    "task_invocation_parameters_tlsverify",
}

_TIER1_RESULT_IDS = {
    "task_results",
    "task_result_name",
    "task_result_type",
    "task_result_value",
}

_TIER1_STEP_IDS = {
    "task_steps",
    "task_step_environment_container",
    "task_step_environment_image",
}

_TIER1_ALLOWED = (
    _TIER1_TOP_LEVEL_IDS
    | _TIER1_PREDICATE_IDS
    | _TIER1_TASK_IDS
    | _TIER1_RESULT_IDS
    | _TIER1_STEP_IDS
)


# ─── Tier 1: Field-level instructions ────────────────────────────────────────

def _instruction_text_tier1(entry: dict) -> str:
    """Generate a natural language instruction for a single-field check."""
    path = entry["path"]
    values = entry["observed_values"]
    desc = entry["description"]
    vtype = entry["value_type"]

    # Presence check for arrays / containers
    if values and isinstance(values[0], str) and values[0].startswith("<array of"):
        return (
            f"Write a Rego deny rule that rejects the attestation if the "
            f"field `{path}` is missing or empty. "
            f"({desc})"
        )

    # Boolean fields
    if vtype == "boolean":
        val = values[0] if values else False
        expected = "true" if val else "false"
        return (
            f"Write a Rego deny rule that rejects the attestation if "
            f"`{path}` is not `{expected}`. "
            f"({desc})"
        )

    # String fields with a URI or known constant value
    if vtype == "string" and values:
        val = values[0]
        # Timestamps — check presence, not exact value
        if re.match(r"^\d{4}-\d{2}-\d{2}T", str(val)):
            return (
                f"Write a Rego deny rule that rejects the attestation if "
                f"`{path}` is missing or is not a valid ISO-8601 timestamp. "
                f"({desc})"
            )
        # SHA digests — check format
        if re.match(r"^(sha256:)?[0-9a-f]{40,}$", str(val)):
            return (
                f"Write a Rego deny rule that rejects the attestation if "
                f"`{path}` is missing or does not match the expected "
                f"sha256 digest format. ({desc})"
            )
        # URIs
        if str(val).startswith("http") or str(val).startswith("oci://"):
            return (
                f"Write a Rego deny rule that rejects the attestation if "
                f"`{path}` is not `\"{val}\"`. "
                f"({desc})"
            )
        # Short known values
        if len(str(val)) < 80:
            return (
                f"Write a Rego deny rule that rejects the attestation if "
                f"`{path}` is not `\"{val}\"`. "
                f"({desc})"
            )

    # Fallback: presence check
    return (
        f"Write a Rego deny rule that rejects the attestation if the "
        f"field `{path}` is missing. ({desc})"
    )


def generate_tier1(catalog: list[dict]) -> list[dict]:
    """Generate Tier 1 (field-level) instructions from the catalog."""
    instructions = []
    seen_ids = set()

    for entry in catalog:
        eid = entry["id"]
        if eid in _SKIP_IDS:
            continue
        if eid not in _TIER1_ALLOWED:
            continue
        if eid in seen_ids:
            continue
        seen_ids.add(eid)

        # Pick a representative value for mock data
        values = entry["observed_values"]
        if values and not (isinstance(values[0], str) and values[0].startswith("<array")):
            mock_val = values[0]
        elif entry["value_type"] == "boolean":
            mock_val = values[0] if values else False
        elif entry["value_type"] == "string":
            mock_val = "example-value"
        else:
            mock_val = "example"

        instruction_id = f"{_sanitize_package_name(eid)}_check"
        mock = _build_mock_from_path(entry["path"], mock_val)

        instructions.append({
            "id": instruction_id,
            "tier": 1,
            "catalog_ids": [eid],
            "instruction": _instruction_text_tier1(entry),
            "package_name": instruction_id,
            "input_paths": [entry["path"]],
            "mock_data": mock,
        })

    return instructions


# ─── Tier 2: Pattern-level instructions ──────────────────────────────────────

def generate_tier2(catalog: list[dict]) -> list[dict]:
    """
    Generate Tier 2 (pattern-level) instructions.

    These iterate across tasks/subjects checking that a property holds for
    ALL or SOME elements.
    """
    instructions = []
    catalog_by_id: dict[str, dict] = {}
    for entry in catalog:
        # Keep first occurrence for duplicate IDs
        if entry["id"] not in catalog_by_id:
            catalog_by_id[entry["id"]] = entry

    # ── All tasks must have status "Succeeded" ────────────────────────────
    instructions.append({
        "id": "all_tasks_succeeded",
        "tier": 2,
        "catalog_ids": ["task_status"],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if any task "
            "in `.predicate.buildConfig.tasks` does not have `status` equal "
            "to `\"Succeeded\"`."
        ),
        "package_name": "all_tasks_succeeded",
        "input_paths": [
            ".predicate.buildConfig.tasks[*].status",
        ],
        "mock_data": {
            "predicate": {
                "buildConfig": {
                    "tasks": [
                        {"name": "build", "status": "Succeeded"},
                        {"name": "test", "status": "Failed"},
                    ]
                }
            }
        },
    })

    # ── All tasks must use bundles resolver ────────────────────────────────
    instructions.append({
        "id": "all_tasks_bundles_resolver",
        "tier": 2,
        "catalog_ids": ["task_ref_resolver"],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if any task "
            "in `.predicate.buildConfig.tasks` does not use `\"bundles\"` as "
            "its `.ref.resolver`."
        ),
        "package_name": "all_tasks_bundles_resolver",
        "input_paths": [
            ".predicate.buildConfig.tasks[*].ref.resolver",
        ],
        "mock_data": {
            "predicate": {
                "buildConfig": {
                    "tasks": [
                        {"name": "build", "ref": {"resolver": "bundles"}},
                        {"name": "test", "ref": {"resolver": "git"}},
                    ]
                }
            }
        },
    })

    # ── All tasks must have a name ────────────────────────────────────────
    instructions.append({
        "id": "all_tasks_have_name",
        "tier": 2,
        "catalog_ids": ["task_name"],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if any task "
            "in `.predicate.buildConfig.tasks` is missing the `name` field."
        ),
        "package_name": "all_tasks_have_name",
        "input_paths": [
            ".predicate.buildConfig.tasks[*].name",
        ],
        "mock_data": {
            "predicate": {
                "buildConfig": {
                    "tasks": [
                        {"name": "build", "status": "Succeeded"},
                        {"status": "Succeeded"},
                    ]
                }
            }
        },
    })

    # ── All tasks must have a serviceAccountName ──────────────────────────
    instructions.append({
        "id": "all_tasks_have_service_account",
        "tier": 2,
        "catalog_ids": ["task_service_account_name"],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if any task "
            "in `.predicate.buildConfig.tasks` is missing the "
            "`serviceAccountName` field or it is empty."
        ),
        "package_name": "all_tasks_have_service_account",
        "input_paths": [
            ".predicate.buildConfig.tasks[*].serviceAccountName",
        ],
        "mock_data": {
            "predicate": {
                "buildConfig": {
                    "tasks": [
                        {"name": "build", "serviceAccountName": "pipeline"},
                        {"name": "test", "serviceAccountName": ""},
                    ]
                }
            }
        },
    })

    # ── All tasks must have startedOn and finishedOn timestamps ───────────
    instructions.append({
        "id": "all_tasks_have_timestamps",
        "tier": 2,
        "catalog_ids": ["task_started_on", "task_finished_on"],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if any task "
            "in `.predicate.buildConfig.tasks` is missing either `startedOn` "
            "or `finishedOn` timestamps."
        ),
        "package_name": "all_tasks_have_timestamps",
        "input_paths": [
            ".predicate.buildConfig.tasks[*].startedOn",
            ".predicate.buildConfig.tasks[*].finishedOn",
        ],
        "mock_data": {
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
                    ]
                }
            }
        },
    })

    # ── All task refs must have the three required params (name, bundle, kind)
    instructions.append({
        "id": "all_task_refs_have_required_params",
        "tier": 2,
        "catalog_ids": ["task_ref_params", "task_ref_params_name"],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if any task's "
            "`.ref.params` does not include all three required parameter names: "
            "`\"name\"`, `\"bundle\"`, and `\"kind\"`."
        ),
        "package_name": "all_task_refs_have_required_params",
        "input_paths": [
            ".predicate.buildConfig.tasks[*].ref.params[*].name",
        ],
        "mock_data": {
            "predicate": {
                "buildConfig": {
                    "tasks": [
                        {
                            "name": "build",
                            "ref": {
                                "resolver": "bundles",
                                "params": [
                                    {"name": "name", "value": "buildah"},
                                    {"name": "bundle", "value": "quay.io/example/task@sha256:abc"},
                                    {"name": "kind", "value": "task"},
                                ],
                            },
                        },
                        {
                            "name": "test",
                            "ref": {
                                "resolver": "bundles",
                                "params": [
                                    {"name": "name", "value": "test-task"},
                                ],
                            },
                        },
                    ]
                }
            }
        },
    })

    # ── All subjects must have a sha256 digest ────────────────────────────
    instructions.append({
        "id": "all_subjects_have_digest",
        "tier": 2,
        "catalog_ids": ["subject_digest_sha256"],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if any "
            "subject in `.subject` is missing a `digest.sha256` field."
        ),
        "package_name": "all_subjects_have_digest",
        "input_paths": [
            ".subject[*].digest.sha256",
        ],
        "mock_data": {
            "subject": [
                {"name": "image1", "digest": {"sha256": "abc123def456"}},
                {"name": "image2"},
            ]
        },
    })

    # ── All subjects must have a name ─────────────────────────────────────
    instructions.append({
        "id": "all_subjects_have_name",
        "tier": 2,
        "catalog_ids": ["subject_name"],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if any "
            "subject in `.subject` is missing the `name` field."
        ),
        "package_name": "all_subjects_have_name",
        "input_paths": [
            ".subject[*].name",
        ],
        "mock_data": {
            "subject": [
                {"name": "quay.io/example/image", "digest": {"sha256": "abc123"}},
                {"digest": {"sha256": "def456"}},
            ]
        },
    })

    # ── All materials must have a digest ──────────────────────────────────
    instructions.append({
        "id": "all_materials_have_digest",
        "tier": 2,
        "catalog_ids": ["predicate_materials_digest_sha256"],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if any "
            "material in `.predicate.materials` is missing a `digest` field "
            "with at least a `sha256` or `sha1` entry."
        ),
        "package_name": "all_materials_have_digest",
        "input_paths": [
            ".predicate.materials[*].digest",
        ],
        "mock_data": {
            "predicate": {
                "materials": [
                    {"uri": "oci://quay.io/example/image", "digest": {"sha256": "abc123"}},
                    {"uri": "oci://quay.io/example/other"},
                ]
            }
        },
    })

    # ── All materials must have a URI ─────────────────────────────────────
    instructions.append({
        "id": "all_materials_have_uri",
        "tier": 2,
        "catalog_ids": ["predicate_materials_uri"],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if any "
            "material in `.predicate.materials` is missing the `uri` field."
        ),
        "package_name": "all_materials_have_uri",
        "input_paths": [
            ".predicate.materials[*].uri",
        ],
        "mock_data": {
            "predicate": {
                "materials": [
                    {"uri": "oci://quay.io/example/image", "digest": {"sha256": "abc123"}},
                    {"digest": {"sha256": "def456"}},
                ]
            }
        },
    })

    # ── Tasks producing results must have IMAGE_DIGEST ────────────────────
    instructions.append({
        "id": "build_tasks_have_image_digest_result",
        "tier": 2,
        "catalog_ids": ["task_result_name"],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if any "
            "task whose name starts with `\"build-container\"` does not have "
            "a result named `\"IMAGE_DIGEST\"`."
        ),
        "package_name": "build_tasks_have_image_digest_result",
        "input_paths": [
            ".predicate.buildConfig.tasks[*].name",
            ".predicate.buildConfig.tasks[*].results[*].name",
        ],
        "mock_data": {
            "predicate": {
                "buildConfig": {
                    "tasks": [
                        {
                            "name": "build-container-amd64",
                            "results": [
                                {"name": "IMAGE_DIGEST", "type": "string", "value": "sha256:abc"},
                                {"name": "IMAGE_URL", "type": "string", "value": "quay.io/ex"},
                            ],
                        },
                        {
                            "name": "build-container-arm64",
                            "results": [
                                {"name": "IMAGE_URL", "type": "string", "value": "quay.io/ex"},
                            ],
                        },
                    ]
                }
            }
        },
    })

    # ── All tasks must have at least one step ─────────────────────────────
    instructions.append({
        "id": "all_tasks_have_steps",
        "tier": 2,
        "catalog_ids": ["task_steps"],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if any task "
            "in `.predicate.buildConfig.tasks` has an empty or missing `steps` "
            "array."
        ),
        "package_name": "all_tasks_have_steps",
        "input_paths": [
            ".predicate.buildConfig.tasks[*].steps",
        ],
        "mock_data": {
            "predicate": {
                "buildConfig": {
                    "tasks": [
                        {
                            "name": "build",
                            "steps": [
                                {"environment": {"container": "build", "image": "quay.io/ex"}}
                            ],
                        },
                        {
                            "name": "test",
                            "steps": [],
                        },
                    ]
                }
            }
        },
    })

    return instructions


# ─── Tier 3: Composite / semantic instructions ───────────────────────────────

def generate_tier3(catalog: list[dict]) -> list[dict]:
    """
    Generate Tier 3 (composite/semantic) instructions.

    These are cross-cutting rules that combine multiple fields for
    real-world policy logic.  They require understanding the *meaning*
    of fields, not just their structure.
    """
    instructions = []

    # ── Succeeded tasks with IMAGE_DIGEST ─────────────────────────────────
    instructions.append({
        "id": "image_digest_requires_succeeded",
        "tier": 3,
        "catalog_ids": ["task_status", "task_result_name"],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if any task "
            "that produces an `IMAGE_DIGEST` result did not complete with "
            "status `\"Succeeded\"`. The rule should iterate over all tasks, "
            "check if a result named `\"IMAGE_DIGEST\"` exists, and if so, "
            "verify the task's `status` is `\"Succeeded\"`."
        ),
        "package_name": "image_digest_requires_succeeded",
        "input_paths": [
            ".predicate.buildConfig.tasks[*].status",
            ".predicate.buildConfig.tasks[*].results[*].name",
        ],
        "mock_data": {
            "predicate": {
                "buildConfig": {
                    "tasks": [
                        {
                            "name": "build-container-amd64",
                            "status": "Succeeded",
                            "results": [
                                {"name": "IMAGE_DIGEST", "type": "string",
                                 "value": "sha256:abc123"},
                            ],
                        },
                        {
                            "name": "build-container-arm64",
                            "status": "Failed",
                            "results": [
                                {"name": "IMAGE_DIGEST", "type": "string",
                                 "value": "sha256:def456"},
                            ],
                        },
                    ]
                }
            }
        },
    })

    # ── Build must be hermetic ────────────────────────────────────────────
    instructions.append({
        "id": "hermetic_build_required",
        "tier": 3,
        "catalog_ids": [
            "predicate_invocation_parameters_hermetic",
            "task_invocation_parameters_hermetic",
        ],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if the build "
            "was not performed hermetically. Check that "
            "`.predicate.invocation.parameters.hermetic` is `\"true\"`. "
            "Additionally, verify that build-container tasks also have their "
            "individual `HERMETIC` parameter set to `\"true\"`."
        ),
        "package_name": "hermetic_build_required",
        "input_paths": [
            ".predicate.invocation.parameters.hermetic",
            ".predicate.buildConfig.tasks[*].invocation.parameters.HERMETIC",
        ],
        "mock_data": {
            "predicate": {
                "invocation": {
                    "parameters": {"hermetic": "true"},
                },
                "buildConfig": {
                    "tasks": [
                        {
                            "name": "build-container-amd64",
                            "invocation": {"parameters": {"HERMETIC": "true"}},
                        },
                        {
                            "name": "build-container-arm64",
                            "invocation": {"parameters": {"HERMETIC": "false"}},
                        },
                    ]
                },
            }
        },
    })

    # ── Builder identity must be a known trusted builder ──────────────────
    instructions.append({
        "id": "trusted_builder_id",
        "tier": 3,
        "catalog_ids": ["predicate_builder_id", "predicate_build_type"],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if the "
            "`.predicate.builder.id` is not `\"https://tekton.dev/chains/v2\"` "
            "OR the `.predicate.buildType` is not "
            "`\"tekton.dev/v1beta1/PipelineRun\"`. Both fields must match "
            "their expected values for the attestation to be accepted."
        ),
        "package_name": "trusted_builder_id",
        "input_paths": [
            ".predicate.builder.id",
            ".predicate.buildType",
        ],
        "mock_data": {
            "predicate": {
                "builder": {"id": "https://tekton.dev/chains/v2"},
                "buildType": "tekton.dev/v1beta1/PipelineRun",
            }
        },
    })

    # ── Subjects must correspond to build task results ────────────────────
    instructions.append({
        "id": "subjects_match_build_results",
        "tier": 3,
        "catalog_ids": ["subject_digest_sha256", "task_result_name", "task_result_value"],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if any "
            "subject's `digest.sha256` does not appear as an `IMAGE_DIGEST` "
            "result value in any task under `.predicate.buildConfig.tasks`. "
            "This ensures every attested image was actually produced by a task "
            "in the pipeline."
        ),
        "package_name": "subjects_match_build_results",
        "input_paths": [
            ".subject[*].digest.sha256",
            ".predicate.buildConfig.tasks[*].results[*].name",
            ".predicate.buildConfig.tasks[*].results[*].value",
        ],
        "mock_data": {
            "subject": [
                {"name": "quay.io/example/image", "digest": {"sha256": "abc123"}},
                {"name": "quay.io/example/image2", "digest": {"sha256": "orphan999"}},
            ],
            "predicate": {
                "buildConfig": {
                    "tasks": [
                        {
                            "name": "build-container",
                            "results": [
                                {"name": "IMAGE_DIGEST", "type": "string",
                                 "value": "sha256:abc123"},
                            ],
                        },
                    ]
                }
            },
        },
    })

    # ── Git material must match invocation revision ───────────────────────
    instructions.append({
        "id": "git_revision_matches_material",
        "tier": 3,
        "catalog_ids": [
            "predicate_invocation_parameters_revision",
            "predicate_materials_uri",
            "predicate_materials_digest_sha1",
        ],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if the "
            "git commit SHA in `.predicate.invocation.parameters.revision` "
            "does not match the `digest.sha1` of the git material in "
            "`.predicate.materials` (the entry whose `uri` starts with "
            "`\"git+\"`). This ensures the build was performed on the "
            "declared source revision."
        ),
        "package_name": "git_revision_matches_material",
        "input_paths": [
            ".predicate.invocation.parameters.revision",
            ".predicate.materials[*].uri",
            ".predicate.materials[*].digest.sha1",
        ],
        "mock_data": {
            "predicate": {
                "invocation": {
                    "parameters": {
                        "revision": "356a767377f0917039b096677333b16bb6c8fbbb",
                    },
                },
                "materials": [
                    {
                        "uri": "oci://quay.io/example/image",
                        "digest": {"sha256": "abc123"},
                    },
                    {
                        "uri": "git+https://github.com/example/repo.git",
                        "digest": {"sha1": "different_sha_mismatch"},
                    },
                ],
            }
        },
    })

    # ── TLS verification must be enabled for all build tasks ──────────────
    instructions.append({
        "id": "tls_verify_enabled",
        "tier": 3,
        "catalog_ids": ["task_invocation_parameters_tlsverify"],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if any "
            "task in `.predicate.buildConfig.tasks` that has a "
            "`TLSVERIFY` invocation parameter set to anything other than "
            "`\"true\"`. Image pushes without TLS verification are a "
            "supply chain risk."
        ),
        "package_name": "tls_verify_enabled",
        "input_paths": [
            ".predicate.buildConfig.tasks[*].invocation.parameters.TLSVERIFY",
        ],
        "mock_data": {
            "predicate": {
                "buildConfig": {
                    "tasks": [
                        {
                            "name": "build-container-amd64",
                            "invocation": {"parameters": {"TLSVERIFY": "true"}},
                        },
                        {
                            "name": "build-container-arm64",
                            "invocation": {"parameters": {"TLSVERIFY": "false"}},
                        },
                    ]
                }
            }
        },
    })

    # ── Build timestamps must be chronological ────────────────────────────
    instructions.append({
        "id": "build_timestamps_chronological",
        "tier": 3,
        "catalog_ids": [
            "predicate_metadata_build_started_on",
            "predicate_metadata_build_finished_on",
        ],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if "
            "`.predicate.metadata.buildStartedOn` is after "
            "`.predicate.metadata.buildFinishedOn`. The build start time "
            "must be earlier than or equal to the build finish time."
        ),
        "package_name": "build_timestamps_chronological",
        "input_paths": [
            ".predicate.metadata.buildStartedOn",
            ".predicate.metadata.buildFinishedOn",
        ],
        "mock_data": {
            "predicate": {
                "metadata": {
                    "buildStartedOn": "2025-05-12T12:20:00Z",
                    "buildFinishedOn": "2025-05-12T12:09:47Z",
                }
            }
        },
    })

    # ── Source repo URL must use HTTPS ─────────────────────────────────────
    instructions.append({
        "id": "source_repo_uses_https",
        "tier": 3,
        "catalog_ids": ["predicate_invocation_parameters_git_url"],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if "
            "`.predicate.invocation.parameters[\"git-url\"]` does not "
            "start with `\"https://\"`. Builds from non-HTTPS sources "
            "are not allowed."
        ),
        "package_name": "source_repo_uses_https",
        "input_paths": [
            ".predicate.invocation.parameters.git-url",
        ],
        "mock_data": {
            "predicate": {
                "invocation": {
                    "parameters": {
                        "git-url": "http://github.com/example/repo",
                    },
                },
            }
        },
    })

    # ── Pipeline must not skip checks ─────────────────────────────────────
    instructions.append({
        "id": "checks_not_skipped",
        "tier": 3,
        "catalog_ids": [
            "predicate_invocation_parameters_skip_checks",
            "predicate_invocation_parameters_rebuild",
        ],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if "
            "`.predicate.invocation.parameters[\"skip-checks\"]` is `\"true\"`. "
            "Production builds must not skip checks."
        ),
        "package_name": "checks_not_skipped",
        "input_paths": [
            ".predicate.invocation.parameters.skip-checks",
        ],
        "mock_data": {
            "predicate": {
                "invocation": {
                    "parameters": {
                        "skip-checks": "true",
                    },
                },
            }
        },
    })

    # ── Task results for scan tasks must contain TEST_OUTPUT ──────────────
    instructions.append({
        "id": "scan_tasks_have_test_output",
        "tier": 3,
        "catalog_ids": ["task_name", "task_result_name"],
        "instruction": (
            "Write a Rego deny rule that rejects the attestation if any task "
            "whose name contains `\"scan\"` or `\"sast\"` does not have a "
            "result named `\"TEST_OUTPUT\"`. Security scan tasks must produce "
            "test output."
        ),
        "package_name": "scan_tasks_have_test_output",
        "input_paths": [
            ".predicate.buildConfig.tasks[*].name",
            ".predicate.buildConfig.tasks[*].results[*].name",
        ],
        "mock_data": {
            "predicate": {
                "buildConfig": {
                    "tasks": [
                        {
                            "name": "clair-scan",
                            "status": "Succeeded",
                            "results": [
                                {"name": "TEST_OUTPUT", "type": "string", "value": "{}"},
                                {"name": "SCAN_OUTPUT", "type": "string", "value": "{}"},
                            ],
                        },
                        {
                            "name": "sast-snyk-check",
                            "status": "Succeeded",
                            "results": [
                                {"name": "REPORTS", "type": "string", "value": "{}"},
                            ],
                        },
                    ]
                }
            }
        },
    })

    return instructions


# ─── Main ─────────────────────────────────────────────────────────────────────

def derive_instructions(catalog_path: str, output_path: str) -> list[dict]:
    """Derive all instruction tiers from the field catalog."""
    catalog = _load_catalog(catalog_path)

    tier1 = generate_tier1(catalog)
    tier2 = generate_tier2(catalog)
    tier3 = generate_tier3(catalog)

    all_instructions = tier1 + tier2 + tier3

    # Deduplicate by id (shouldn't happen, but safety net)
    seen: set[str] = set()
    deduped: list[dict] = []
    for inst in all_instructions:
        if inst["id"] not in seen:
            seen.add(inst["id"])
            deduped.append(inst)

    # Write output
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    with open(output, "w", encoding="utf-8") as f:
        for inst in deduped:
            f.write(json.dumps(inst, default=str) + "\n")

    # Summary
    tier_counts = defaultdict(int)
    for inst in deduped:
        tier_counts[inst["tier"]] += 1

    print(f"Catalog:  {catalog_path}  ({len(catalog)} entries)")
    print(f"Output:   {output_path}")
    print(f"Total instructions: {len(deduped)}")
    print()
    print("Instructions by tier:")
    for tier in [1, 2, 3]:
        label = {1: "field-level", 2: "pattern-level", 3: "composite"}[tier]
        print(f"  Tier {tier} ({label:14s}): {tier_counts.get(tier, 0):4d}")
    print()

    # Print examples from each tier
    for tier in [1, 2, 3]:
        tier_insts = [i for i in deduped if i["tier"] == tier]
        if tier_insts:
            example = tier_insts[0]
            print(f"Example Tier {tier}:")
            print(f"  id:          {example['id']}")
            print(f"  instruction: {example['instruction'][:120]}...")
            print(f"  paths:       {example['input_paths']}")
            print()

    return deduped


def main():
    parser = argparse.ArgumentParser(
        description="Phase 1: Derive natural language instructions from field catalog."
    )
    parser.add_argument(
        "--catalog", type=str,
        default="phase0_catalog/output/field_catalog.jsonl",
        help="Path to the field catalog JSONL (default: phase0_catalog/output/field_catalog.jsonl).",
    )
    parser.add_argument(
        "--output", type=str,
        default="phase1_instructions/output/instructions.jsonl",
        help="Output path (default: phase1_instructions/output/instructions.jsonl).",
    )
    args = parser.parse_args()

    derive_instructions(args.catalog, args.output)


if __name__ == "__main__":
    main()
