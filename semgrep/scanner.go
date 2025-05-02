package semgrep

import (
	"bufio"
	"github.com/califio/code-secure-analyzer"
	"github.com/califio/code-secure-analyzer/logger"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Scanner struct {
	Configs       string
	Severities    string
	ProEngine     bool
	ExcludedPaths string
	Verbose       bool
	Output        string
	ResultOutput  string
	ProjectPath   string
}

func (scanner *Scanner) Type() analyzer.ScannerType {
	return analyzer.ScannerTypeSast
}

func (scanner *Scanner) Name() string {
	return "semgrep"
}

func (scanner *Scanner) Scan(option analyzer.ScanOption) (*analyzer.SastResult, error) {
	var changedFiles []string
	if option.ScanType == analyzer.ChangedFileOnly {
		for _, file := range option.ChangedFiles {
			if file.Status == analyzer.Add || file.Status == analyzer.Modify {
				changedFiles = append(changedFiles, file.To)
			}
		}
	}
	args := scanner.args(changedFiles)
	cmd := exec.Command("semgrep", args...)
	logger.Info(cmd.String())
	cmd.Env = os.Environ()
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	err := cmd.Start()
	if err != nil {
		return nil, err
	}
	go printStdout(stdout)
	go printStdout(stderr)
	err = cmd.Wait()
	if err != nil {
		return nil, err
	}
	reader, _ := os.Open(scanner.Output)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	err = os.Remove(scanner.Output)
	if err != nil {
		logger.Error("Delete output error: " + err.Error())
	}
	return ParseJsonToFindingResult(data)
}

func (scanner *Scanner) args(changedFiles []string) []string {
	args := []string{
		"scan",
		"--no-rewrite-rule-ids",
		"--dataflow-traces",
		"--disable-version-check",
		"--json",
		"--output", scanner.Output,
	}
	if strings.TrimSpace(scanner.ExcludedPaths) != "" {
		excludes := strings.Split(scanner.ExcludedPaths, ",")
		for _, exclude := range excludes {
			args = append(args, "--exclude", strings.TrimSpace(exclude))
		}
	}
	if strings.TrimSpace(scanner.ExcludedPaths) != "" {
		severities := strings.Split(scanner.Severities, ",")
		for _, severity := range severities {
			if severity == "INFO" || severity == "WARNING" || severity == "ERROR" {
				args = append(args, "--severity", strings.TrimSpace(severity))
			}
		}
	}

	if scanner.ProEngine {
		args = append(args, "--pro")
	}

	if strings.TrimSpace(scanner.Configs) != "" {
		configs := strings.Split(scanner.Configs, ",")
		for _, config := range configs {
			args = append(args, "--config", strings.TrimSpace(config))
		}
	}
	if scanner.Verbose {
		args = append(args, "--verbose")
	}
	if len(changedFiles) > 0 {
		for _, file := range changedFiles {
			args = append(args, filepath.Join(scanner.ProjectPath, file))
		}
		return args
	} else {
		if scanner.ProjectPath == "" {
			scanner.ProjectPath = "."
		}
		args = append(args, scanner.ProjectPath)
		return args
	}
}

func printStdout(stdout io.ReadCloser) {
	reader := bufio.NewReader(stdout)
	line, _, err := reader.ReadLine()
	for {
		if err != nil || line == nil {
			break
		}
		logger.Println(string(line))
		line, _, err = reader.ReadLine()
	}
}
