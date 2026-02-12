package normalize_git_url_helper

import rego.v1

normalize_git_url(url) := suffix_git_url(prefix_git_url(url))

prefix_git_url(url) := normalized if {
	not strings.any_prefix_match(url, "git+")
	normalized := sprintf("git+%s", [url])
} else := url

suffix_git_url(url) := normalized if {
	not strings.any_suffix_match(url, ".git")
	normalized := sprintf("%s.git", [url])
} else := url
