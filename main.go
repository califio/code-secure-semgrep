package main

import (
	"gitlab.com/code-secure/analyzer"
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
	sastAnalyzer := analyzer.NewSASTAnalyzer()
	// register scanner
	sastAnalyzer.RegisterScanner(&semgrep.Scanner{
		Configs:       getEnv("SEMGREP_RULES", ""),
		Severities:    getEnv("SEMGREP_SEVERITY", ""),
		ProEngine:     proEngine,
		ExcludedPaths: getEnv("SEMGREP_EXCLUDED_PATHS", ""),
		Verbose:       verbose,
		Output:        getEnv("SEMGREP_OUTPUT", "semgrep.json"),
		ProjectPath:   getEnv("PROJECT_PATH", ""),
	})
	sastAnalyzer.Run()
}
