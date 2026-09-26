package middleware

import "testing"

func TestValidateRepoName(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "valid repo", value: "core-api", wantErr: false},
		{name: "empty repo", value: "", wantErr: true},
		{name: "invalid chars", value: "repo/../secret", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRepoName(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateRepoName(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestValidateUserLogin(t *testing.T) {
	if err := ValidateUserLogin("octocat"); err != nil {
		t.Fatalf("ValidateUserLogin returned unexpected error: %v", err)
	}

	if err := ValidateUserLogin("bad login"); err == nil {
		t.Fatal("ValidateUserLogin accepted invalid login")
	}
}

func TestValidateRepoFullName(t *testing.T) {
	for _, ok := range []string{"XtReL/devsecops-gatekeeper", "org/my.repo_1"} {
		if err := ValidateRepoFullName(ok); err != nil {
			t.Fatalf("rejected valid %q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "noslash", "a/b/c", "owner/../x", "own er/repo", "owner/repo;rm"} {
		if err := ValidateRepoFullName(bad); err == nil {
			t.Fatalf("accepted invalid %q", bad)
		}
	}
}
