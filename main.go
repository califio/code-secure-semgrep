package main

import (
	"github.com/alecthomas/kong"
	"gitlab.com/code-secure/analyzer"
	"semgrep/semgrep"
)

type RunCmd struct {
	SemgrepRules         string `help:"Semgrep rules" env:"SEMGREP_RULES" default:""`
	SemgrepSeverity      string `help:"Semgrep Severity" env:"SEMGREP_SEVERITY" default:""`
	SemgrepExcludedPaths string `help:"Semgrep Severity" env:"SEMGREP_EXCLUDED_PATHS" default:""`
	Pro                  bool   `help:"Scan with pro engine" env:"SEMGREP_PRO" default:"true"`
	Verbose              bool   `help:"Verbose" env:"SEMGREP_VERBOSE" default:"false"`
	Output               string `help:"Output result" env:"SEMGREP_OUTPUT" default:"semgrep.json"`
	ProjectPath          string `help:"Project path" env:"PROJECT_PATH" default:""`
}

func (r *RunCmd) Run() error {
	sastAnalyzer := analyzer.NewFindingAnalyzer()
	// register scanner
	sastAnalyzer.RegisterScanner(&semgrep.Scanner{
		Configs:       r.SemgrepRules,
		Severities:    r.SemgrepSeverity,
		ProEngine:     r.Pro,
		ExcludedPaths: r.SemgrepExcludedPaths,
		Verbose:       r.Verbose,
		Output:        r.Output,
		ProjectPath:   r.ProjectPath,
	})
	sastAnalyzer.Run()
	return nil
}

var cli struct {
	Run RunCmd `cmd:"" help:"Semgrep scan SAST"`
}

func main() {
	ctx := kong.Parse(&cli, kong.Name("analyzer"), kong.UsageOnError())
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}
