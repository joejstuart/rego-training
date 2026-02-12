package normalize_git_url_helper_test

import data.normalize_git_url_helper
import rego.v1

test_adds_prefix_and_suffix_if_missing if {
	url := "https://github.com/acme/repo"
	normalize_git_url_helper.normalize_git_url(url) == "git+https://github.com/acme/repo.git"
}

test_keeps_existing_prefix_and_suffix if {
	url := "git+https://github.com/acme/repo.git"
	normalize_git_url_helper.normalize_git_url(url) == "git+https://github.com/acme/repo.git"
}
