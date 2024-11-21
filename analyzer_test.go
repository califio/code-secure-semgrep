package main

import (
	"gitlab.com/code-secure/analyzer"
	"os"
	"semgrep/semgrep"
	"testing"
)

func initEnv() {
	os.Setenv("GITLAB_TOKEN", "change_me")
	os.Setenv("CI_SERVER_URL", "https://gitlab.com")
	//os.Setenv("CI_MERGE_REQUEST_IID", "18")
	os.Setenv("CI_PROJECT_ID", "50471841")
	os.Setenv("CI_PROJECT_URL", "https://gitlab.com/0xduo/vulnado2")
	os.Setenv("CI_PROJECT_NAME", "vulnado2")
	os.Setenv("CI_PROJECT_NAMESPACE", "0xduo")
	os.Setenv("CI_COMMIT_TITLE", "Commit Test2")
	os.Setenv("CI_COMMIT_BRANCH", "main")
	os.Setenv("CI_DEFAULT_BRANCH", "main")
	os.Setenv("CI_JOB_URL", "https://gitlab.com/0xduo/vulnado/-/jobs/8241092355")
	os.Setenv("CI_COMMIT_SHA", "891832b2fdecb72c444af1a6676eba6eb40435ab")
	os.Setenv("CODE_SECURE_TOKEN", "962ba2f962eb4e4abb6679d3bae259906da2d320dc924cb29ed12a83a6fdfdad")
	os.Setenv("CODE_SECURE_SERVER", "http://localhost:5272")
}

func TestScanAnalyzer(t *testing.T) {
	initEnv()
	os.Setenv("PROJECT_PATH", "../../vulnado")
	newAnalyzer := analyzer.NewSASTAnalyzer()
	// register semgrep
	newAnalyzer.RegisterScanner(&semgrep.Scanner{
		Configs:       getEnv("SEMGREP_RULES", ""),
		Severities:    getEnv("SEMGREP_SEVERITY", ""),
		ProEngine:     true,
		ExcludedPaths: getEnv("SEMGREP_EXCLUDED_PATHS", ""),
		Verbose:       false,
		Output:        getEnv("SEMGREP_OUTPUT", "semgrep.json"),
		ProjectPath:   getEnv("PROJECT_PATH", "."),
	})
	// run
	newAnalyzer.Run()
}
