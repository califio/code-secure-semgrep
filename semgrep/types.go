package semgrep

import "gitlab.com/code-secure/analyzer/api"

type Region struct {
	Col    int `json:"col"`
	Line   int `json:"line"`
	Offset int `json:"offset"`
}

type Location struct {
	End   Region `json:"end"`
	Path  string `json:"path"`
	Start Region `json:"start"`
}

type TaintLocation struct {
	Location Location `json:"location"`
	Content  string   `json:"content"`
}

type Metadata struct {
	Confidence         string   `json:"confidence"`
	Cwe                []string `json:"cwe"`
	Impact             string   `json:"impact"`
	References         []string `json:"references"`
	Source             string   `json:"source"`
	VulnerabilityClass []string `json:"vulnerability_class"`
}

type Node struct {
	Content  string   `json:"content"`
	Location Location `json:"location"`
}
type DataFlow struct {
	IntermediateVars []Node        `json:"intermediate_vars"`
	TaintSink        []interface{} `json:"taint_sink"`
	TaintSource      []interface{} `json:"taint_source"`
}
type Extract struct {
	Fingerprint string    `json:"fingerprint"`
	Lines       string    `json:"lines"`
	Message     string    `json:"message"`
	Metadata    Metadata  `json:"metadata"`
	Severity    string    `json:"severity"`
	Dataflow    *DataFlow `json:"dataflow_trace,omitempty"`
}

func (m *Result) Severity() string {
	if m.Extra.Metadata.Impact != "" {
		switch m.Extra.Metadata.Impact {
		case "HIGH":
			return api.SeverityHigh
		case "MEDIUM":
			return api.SeverityMedium
		case "LOW":
			return api.SeverityLow
		default:
			return api.SeverityInfo
		}
	}
	if m.Extra.Severity != "" {
		switch m.Extra.Severity {
		case "ERROR":
			return api.SeverityHigh
		case "WARNING":
			return api.SeverityMedium
		default:
			return api.SeverityInfo
		}
	}
	return api.SeverityInfo
}

type Result struct {
	CheckId string  `json:"check_id"`
	End     Region  `json:"end"`
	Extra   Extract `json:"extra"`
	Path    string  `json:"path"`
	Start   Region  `json:"start"`
}

type Report struct {
	Results []Result `json:"results"`
	Version string   `json:"version"`
}
