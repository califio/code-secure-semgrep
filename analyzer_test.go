package main

import (
	"github.com/califio/code-secure-analyzer"
	"github.com/joho/godotenv"
	"os"
	"semgrep/semgrep"
	"testing"
)

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
