package models

type ScanTask struct {
	TenantID  int64  `json:"tenant_id"`
	RepoName  string `json:"repo_name"`
	CloneURL  string `json:"clone_url"`
	CommitSHA string `json:"commit_sha"` // [NEW] Криптографический якорь коммита
}
