package semgrep

import (
	"encoding/json"
	"fmt"
	"gitlab.com/code-secure/analyzer/finding"
	"reflect"
	"strings"
)

func ParseJsonToSASTFindings(data []byte) ([]finding.SASTFinding, error) {
	var report Report
	err := json.Unmarshal(data, &report)
	if err != nil {
		return nil, err
	}
	return ConvertReportToSASTFindings(report), err
}

func ConvertReportToSASTFindings(report Report) []finding.SASTFinding {
	var findings []finding.SASTFinding
	for _, result := range report.Results {
		name := fmt.Sprintf("%s at %s:%d", slugToNormalText(result.CheckId), result.Path, result.Start.Line)
		category := "Other"
		if len(result.Extra.Metadata.VulnerabilityClass) > 0 {
			category = result.Extra.Metadata.VulnerabilityClass[0]
		}
		description := result.Extra.Message
		//dataflow
		var findingFlows []finding.Location
		if result.Extra.Dataflow != nil {
			var taintFlows []*TaintLocation
			taintSource := ConvertCliLoc(result.Extra.Dataflow.TaintSource)
			if taintSource != nil {
				taintFlows = append(taintFlows, taintSource)
			}
			taintSinks := ConvertCliCall(result.Extra.Dataflow.TaintSink)
			if len(taintSinks) == 0 {
				taintSink := ConvertCliLoc(result.Extra.Dataflow.TaintSink)
				if taintSink != nil {
					taintSinks = append(taintSinks, taintSink)
				}
			}
			taintFlows = append(taintFlows, taintSinks...)
			if len(taintFlows) > 0 {
				for _, taint := range taintFlows {
					findingFlows = append(findingFlows, finding.Location{
						Path:        taint.Location.Path,
						Snippet:     taint.Content,
						StartLine:   taint.Location.Start.Line,
						EndLine:     taint.Location.End.Line,
						StartColumn: taint.Location.Start.Col,
						EndColumn:   taint.Location.End.Col,
					})
				}
			}
		}
		//cwe
		if len(result.Extra.Metadata.Cwe) > 0 {
			description += "\n\n___\n**CWE**\n"
			for _, cwe := range result.Extra.Metadata.Cwe {
				description += fmt.Sprintf("- %s\n", cwe)
			}
		}
		//owasp
		if len(result.Extra.Metadata.Owasp) > 0 {
			description += "\n\n___\n**OWASP**\n"
			for _, s := range result.Extra.Metadata.Owasp {
				description += fmt.Sprintf("- %s\n", s)
			}
		}
		//reference
		if len(result.Extra.Metadata.References) > 0 {
			description += "\n\n___\n**References**\n"
			for _, s := range result.Extra.Metadata.References {
				description += fmt.Sprintf("- %s\n", s)
			}
		}
		//source
		if result.Extra.Metadata.Source != "" {
			description += "\n\n___\n**Source**\n"
			description += fmt.Sprintf("- %s\n", result.Extra.Metadata.Source)
		}
		issue := finding.SASTFinding{
			RuleID:         result.CheckId,
			Identity:       result.Extra.Fingerprint,
			Name:           name,
			Description:    description,
			Recommendation: "",
			Category:       category,
			Severity:       result.Severity(),
			Location: &finding.Location{
				Path:        result.Path,
				Snippet:     result.Extra.Lines,
				StartLine:   result.Start.Line,
				EndLine:     result.End.Line,
				StartColumn: result.Start.Col,
				EndColumn:   result.End.Col,
			},
			FindingFlow: findingFlows,
		}
		findings = append(findings, issue)
	}
	return findings
}

func ConvertCliLoc(node []interface{}) *TaintLocation {
	if len(node) == 2 && reflect.TypeOf(node[0]).Kind() == reflect.String && node[0].(string) == "CliLoc" && reflect.TypeOf(node[1]).Kind() == reflect.Slice {
		locNode := node[1].([]interface{})
		return convertLocNode(locNode)
	}
	return nil
}

func ConvertCliCall(node []interface{}) []*TaintLocation {
	var result []*TaintLocation
	if len(node) == 2 && reflect.TypeOf(node[0]).Kind() == reflect.String && node[0].(string) == "CliCall" && reflect.TypeOf(node[1]).Kind() == reflect.Slice {
		callNode := node[1].([]interface{})
		if len(callNode) == 3 {
			if reflect.TypeOf(callNode[0]).Kind() == reflect.Slice {
				taint := convertLocNode(callNode[0].([]interface{}))
				if taint != nil {
					result = append(result, taint)
				}
			}
			if reflect.TypeOf(callNode[1]).Kind() == reflect.Slice {
				for _, taintNode := range callNode[1].([]interface{}) {
					data, _ := json.Marshal(taintNode)
					var taint TaintLocation
					err := json.Unmarshal(data, &taint)
					if err == nil && taint.Location.Path != "" {
						result = append(result, &taint)
					}
				}
			}
			if reflect.TypeOf(callNode[2]).Kind() == reflect.Slice {
				taint := ConvertCliLoc(callNode[2].([]interface{}))
				if taint != nil {
					result = append(result, taint)
				}
			}
		}
	}
	return result
}

func convertLocNode(node []interface{}) *TaintLocation {
	if len(node) == 2 && reflect.TypeOf(node[1]).Kind() == reflect.String {
		data, _ := json.Marshal(node[0])
		var location Location
		err := json.Unmarshal(data, &location)
		if err == nil && location.Path != "" {
			return &TaintLocation{
				Location: location,
				Content:  node[1].(string),
			}
		}
	}
	return nil
}

func slugToNormalText(slug string) string {
	parts := strings.Split(slug, ".")
	n := len(parts)
	if n > 1 && parts[n-1] == parts[n-2] {
		parts = parts[:n-1]
	}
	for i, part := range parts {
		subParts := strings.Split(part, "-")
		for j, subPart := range subParts {
			subParts[j] = strings.Title(subPart)
		}
		parts[i] = strings.Join(subParts, " ")
	}
	return strings.Join(parts, " ")
}
