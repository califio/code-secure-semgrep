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
	g, _ := git.NewGitHub()
	fmt.Println(g.MergeRequestID())
	fmt.Println(g.TargetBranchSha())
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
