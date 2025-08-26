package main

import (
	"fmt"
	"github.com/califio/code-secure-analyzer"
	"github.com/califio/code-secure-analyzer/git"
	"github.com/joho/godotenv"
	"os"
	"semgrep/semgrep"
	"testing"
)

func TestGitHubEnv(t *testing.T) {
	_ = godotenv.Load()
	github, _ := git.NewGitHub()
	fmt.Println("ProjectID: " + github.ProjectID())
	fmt.Println("ProjectName: " + github.ProjectName())
	fmt.Println("ProjectURL: " + github.ProjectURL())
	fmt.Println("BlobURL: " + github.BlobURL())
	fmt.Println("DefaultBranch: " + github.DefaultBranch())
	fmt.Println("CommitTitle: " + github.CommitTitle())
	fmt.Println("CommitBranch: " + github.CommitBranch())
	fmt.Println("CommitSha: " + github.CommitSha())
	fmt.Println("MergeRequestID: " + github.MergeRequestID())
	fmt.Println("MergeRequestTitle: " + github.MergeRequestTitle())
	fmt.Println("TargetBranch: " + github.TargetBranch())
	fmt.Println("SourceBranch: " + github.SourceBranch())
	fmt.Println("TargetBranchSha: " + github.TargetBranchSha())
	fmt.Println("CommitTag: " + github.CommitTag())
	fmt.Println("JobURL: " + github.JobURL())
}
func TestScanAnalyzer(t *testing.T) {
	_ = godotenv.Load()
	newAnalyzer := analyzer.NewSastAnalyzer(analyzer.SastAnalyzerOption{
		ProjectPath: ".",
		Scanner: &semgrep.Scanner{
			Configs:       "",
			Severities:    "",
			ProEngine:     false,
			ExcludedPaths: "",
			Verbose:       false,
			Output:        "semgrep.json",
			ProjectPath:   os.Getenv("PROJECT_PATH"),
		},
	})
	// run
	newAnalyzer.Run()
}
