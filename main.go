package main

import (
	"github.com/alecthomas/kong"
	"github.com/califio/code-secure-analyzer"
	"semgrep/semgrep"
)

type RunCmd struct {
	SemgrepRules         string `help:"Semgrep rules" env:"SEMGREP_RULES" default:""`
	SemgrepSeverity      string `help:"Semgrep Severity" env:"SEMGREP_SEVERITY" default:""`
	SemgrepExcludedPaths string `help:"Semgrep Severity" env:"SEMGREP_EXCLUDED_PATHS" default:""`
	Pro                  bool   `help:"Scan with pro engine. Require SEMGREP_APP_TOKEN variable" env:"SEMGREP_PRO" default:"false"`
	Verbose              bool   `help:"Verbose" env:"SEMGREP_VERBOSE" default:"false"`
	Output               string `help:"Semgrep output" env:"SEMGREP_OUTPUT" default:"semgrep.json"`
	ProjectPath          string `help:"Project path" env:"PROJECT_PATH" default:"."`
}

func (r *RunCmd) Run() error {
	sastAnalyzer := analyzer.NewSastAnalyzer(analyzer.SastAnalyzerOption{
		ProjectPath: r.ProjectPath,
		Scanner: &semgrep.Scanner{
			Configs:       r.SemgrepRules,
			Severities:    r.SemgrepSeverity,
			ProEngine:     r.Pro,
			ExcludedPaths: r.SemgrepExcludedPaths,
			Verbose:       r.Verbose,
			Output:        r.Output,
			ProjectPath:   r.ProjectPath,
		},
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
