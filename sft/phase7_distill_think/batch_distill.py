#!/usr/bin/env python3
"""
Batch distillation script for generating reasoning traces.

This script processes the remaining undistilled tasks and generates
high-quality reasoning traces based on established patterns.
"""

import json
import re
from pathlib import Path
from typing import Dict, List

# Completed distillations
COMPLETED = {
    # Tier 1 rule_only
    'predicate_build_type_check', 'predicate_builder_id_check',
    'predicate_invocation_parameters_git_url_check', 'predicate_invocation_parameters_hermetic_check',
    'predicate_invocation_parameters_output_image_check', 'predicate_invocation_parameters_rebuild_check',
    'predicate_invocation_parameters_revision_check', 'predicate_invocation_parameters_skip_checks_check',
    'predicate_materials_check', 'predicate_materials_digest_sha256_check',
    'predicate_materials_uri_check', 'predicate_metadata_build_finished_on_check',
    'predicate_metadata_build_started_on_check', 'predicate_metadata_reproducible_check',
    'predicate_type_check', 'subject_digest_sha256_check',
    'subject_name_check', 'task_finished_on_check',
    'task_invocation_parameters_commit_sha_check', 'task_invocation_parameters_dockerfile_check',
    'task_invocation_parameters_hermetic_check', 'task_invocation_parameters_image_check',
    'task_invocation_parameters_tlsverify_check', 'task_name_check',
    'task_ref_params_name_check', 'task_ref_params_value_check',
    'task_ref_resolver_check', 'task_result_name_check',
    'task_result_type_check', 'task_result_value_check',
    'task_results_check', 'task_service_account_name_check',
    'task_started_on_check', 'task_status_check',
    'task_step_environment_container_check', 'task_step_environment_image_check',
    'task_steps_check', 'type_check',
    # Tier 2 rule_only
    'all_materials_have_digest', 'all_materials_have_uri',
    'all_subjects_have_digest', 'all_subjects_have_name',
    'all_task_refs_have_required_params', 'all_tasks_bundles_resolver',
    'all_tasks_have_name', 'all_tasks_have_service_account',
    'all_tasks_have_steps', 'all_tasks_have_timestamps',
    'all_tasks_succeeded', 'build_tasks_have_image_digest_result',
}

def load_tasks(jsonl_path: Path) -> List[Dict]:
    """Load all unique tasks from JSONL file."""
    tasks = []
    with open(jsonl_path) as f:
        for line in f:
            tasks.append(json.loads(line))
    return tasks

def extract_code_from_response(response: str) -> str:
    """Extract Rego code from assistant response (after </think>)."""
    match = re.search(r'</think>\s*\n+(.*)', response, re.DOTALL)
    if match:
        return match.group(1).strip()
    return response.strip()

def count_remaining():
    """Count how many tasks remain to be distilled."""
    tasks = load_tasks(Path('sft/phase7_distill_think/output/all_unique_tasks.jsonl'))
    
    by_type = {}
    for task in tasks:
        key = (task['type'], task['tier'])
        if key not in by_type:
            by_type[key] = {'total': 0, 'completed': 0}
        by_type[key]['total'] += 1
        
        # Check if completed
        if task['type'] == 'rule_only' and task['tier'] in [1, 2]:
            if task['task_id'] in COMPLETED:
                by_type[key]['completed'] += 1
    
    print("Progress by (type, tier):")
    total_remaining = 0
    for key in sorted(by_type.keys()):
        stats = by_type[key]
        remaining = stats['total'] - stats['completed']
        total_remaining += remaining
        print(f"  {key}: {stats['completed']}/{stats['total']} ({remaining} remaining)")
    
    print(f"\nTotal: {612 - total_remaining}/612 ({total_remaining} remaining)")
    return total_remaining

if __name__ == '__main__':
    count_remaining()
