package main

import (
	"gitlab.com/code-secure/analyzer/analyzer"
	"gitlab.com/code-secure/analyzer/finding"
	"gitlab.com/code-secure/analyzer/handler"
	"os"
	"semgrep/semgrep"
)

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return defaultValue
	}
	return value
}

func main() {
	proEngine := true
	if getEnv("SEMGREP_PRO", "true") != "true" {
		proEngine = false
	}
	verbose := false
	if getEnv("SEMGREP_DEBUG", "false") == "true" || getEnv("SEMGREP_VERBOSE", "false") == "true" {
		verbose = true
	}
	newAnalyzer := analyzer.NewAnalyzer[finding.SASTFinding]()
	// register semgrep
	newAnalyzer.RegisterScanner(&semgrep.Scanner{
		Configs:       getEnv("SEMGREP_RULES", ""),
		Severities:    getEnv("SEMGREP_SEVERITY", ""),
		ProEngine:     proEngine,
		ExcludedPaths: getEnv("SEMGREP_EXCLUDED_PATHS", ""),
		Verbose:       verbose,
		Output:        getEnv("SEMGREP_OUTPUT", "semgrep.json"),
	})
	// register handler
	newAnalyzer.RegisterHandler(handler.GetSASTHandler())
	// run
	newAnalyzer.Run()
}
