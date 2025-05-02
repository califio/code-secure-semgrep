package main

import (
	"github.com/califio/code-secure-analyzer"
	"os"
	"semgrep/semgrep"
	"testing"
)

func initEnv() {
	os.Setenv("GITLAB_CI", "true")
	os.Setenv("GITLAB_TOKEN", "change_me")
	os.Setenv("CI_SERVER_URL", "https://gitlab.com")
	//os.Setenv("CI_MERGE_REQUEST_IID", "18")
	os.Setenv("CI_PROJECT_ID", "66334560")
	os.Setenv("CI_PROJECT_URL", "https://gitlab.com/0xduo/test-vuln")
	os.Setenv("CI_PROJECT_NAME", "test-vuln")
	os.Setenv("CI_PROJECT_NAMESPACE", "0xduo")
	os.Setenv("CI_COMMIT_TITLE", "Commit Test2")
	os.Setenv("CI_COMMIT_BRANCH", "main")
	os.Setenv("CI_DEFAULT_BRANCH", "main")
	os.Setenv("CI_JOB_URL", "https://gitlab.com/0xduo/test-vuln/-/jobs/1")
	os.Setenv("CI_COMMIT_SHA", "565292f74762ba108c82b9f175fbe31fc9f1fe61")
	os.Setenv("CODE_SECURE_TOKEN", "ab1e097840764f7ba093c43194cbaf8bceea50d3bef144d3994262428d176346")
	os.Setenv("CODE_SECURE_URL", "http://localhost:5272")
}

func TestScanAnalyzer(t *testing.T) {
	initEnv()
	newAnalyzer := analyzer.NewSastAnalyzer(analyzer.SastAnalyzerOption{
		ProjectPath: "/tmp/foo",
		Scanner: &semgrep.Scanner{
			Configs:       "",
			Severities:    "",
			ProEngine:     false,
			ExcludedPaths: "",
			Verbose:       false,
			Output:        "semgrep.json",
			ProjectPath:   "/tmp/foo",
		},
	})
	// run
	newAnalyzer.Run()
}
