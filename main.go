package main

import (
	"fmt"
	"github.com/alecthomas/kong"
	"github.com/califio/code-secure-analyzer"
	"github.com/califio/code-secure-analyzer/git"
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

type GitHubCmd struct {
}

func (r *GitHubCmd) Run() error {
	github, _ := git.NewGitHub()
	fmt.Println("ProjectID: " + github.ProjectID())
	fmt.Println("ProjectName: " + github.ProjectName())
	fmt.Println("ProjectURL: " + github.ProjectURL())
	fmt.Println("BlobURL: " + github.BlobURL())
	fmt.Println("DefaultBranch: " + github.DefaultBranch())
	fmt.Println("CommitTitle: " + github.CommitTitle())
	fmt.Println("CommitSha: " + github.CommitSha())
	fmt.Println("MergeRequestID: " + github.MergeRequestID())
	fmt.Println("MergeRequestTitle: " + github.MergeRequestTitle())
	fmt.Println("TargetBranch: " + github.TargetBranch())
	fmt.Println("SourceBranch: " + github.SourceBranch())
	fmt.Println("TargetBranchSha: " + github.TargetBranchSha())
	fmt.Println("CommitTag: " + github.CommitTag())
	fmt.Println("JobURL: " + github.JobURL())
	return nil
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
	Run    RunCmd    `cmd:"run" help:"Semgrep scan SAST"`
	Github GitHubCmd `cmd:"github" help:"Debug github environment variables"`
}

func main() {
	ctx := kong.Parse(&cli, kong.Name("analyzer"), kong.UsageOnError())
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}
