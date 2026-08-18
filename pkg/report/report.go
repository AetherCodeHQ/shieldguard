package report

import (
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "strings"

    "github.com/fatih/color"
    "github.com/Qyroxen/shieldguard/pkg/scanner"
)

type Reporter struct{}

func NewReporter() *Reporter {
    return &Reporter{}
}

func (r *Reporter) PrintSummary(vulns []scanner.Vulnerability) {
    if len(vulns) == 0 {
        color.New(color.FgGreen).Println("[+] No vulnerabilities detected. Your code is secure!")
        return
    }

    color.New(color.FgRed).Printf("[!] Found %d vulnerabilities:\n", len(vulns))
    for _, v := range vulns {
        color.New(color.FgYellow).Printf("  - %s:%d [%s] Severity: %s (score=%.2f)\n", v.FilePath, v.Line, v.Type, v.Severity, v.Score)
    }
    fmt.Println()
}

func (r *Reporter) PrintVulnerabilityWithFix(v scanner.Vulnerability, analysis string, patchText string) {
    color.New(color.FgHiCyan).Printf("==================================================\n")
    color.New(color.FgRed).Printf("Vulnerability: %s:%d (%s) [Severity: %s]\n", v.FilePath, v.Line, v.Type, v.Severity)
    color.New(color.FgWhite).Printf("Snippet: %s\n", v.Snippet)
    color.New(color.FgYellow).Printf("Analysis: %s\n", analysis)
    if patchText != "" {
        color.New(color.FgGreen).Printf("Suggested Fix:\n%s\n", patchText)
    }
    color.New(color.FgHiCyan).Printf("==================================================\n")
}

func (r *Reporter) ExportJSON(outputPath string, vulns []scanner.Vulnerability) error {
    data, err := json.MarshalIndent(vulns, "", "  ")
    if err != nil {
        return err
    }
    return os.WriteFile(outputPath, data, 0644)
}

// ---- SARIF 2.1.0 (GitHub Code Scanning uyumlu) ----

type sarifDocument struct {
    Schema  string     `json:"$schema"`
    Version string     `json:"version"`
    Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
    Tool    sarifTool    `json:"tool"`
    Results []sarifResult `json:"results"`
}

type sarifTool struct {
    Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
    Name           string      `json:"name"`
    Version        string      `json:"version"`
    InformationURI string      `json:"informationUri"`
    Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
    ID                   string            `json:"id"`
    Name                 string            `json:"name"`
    ShortDescription     map[string]string `json:"shortDescription"`
    DefaultConfiguration map[string]string `json:"defaultConfiguration"`
    Properties           map[string]string `json:"properties"`
}

type sarifResult struct {
    RuleID    string            `json:"ruleId"`
    Level     string            `json:"level"`
    Message   map[string]string `json:"message"`
    Locations []sarifLocation   `json:"locations"`
}

type sarifLocation struct {
    PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
    ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
    Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
    URI string `json:"uri"`
}

type sarifRegion struct {
    StartLine int              `json:"startLine"`
    Snippet   map[string]string `json:"snippet"`
}

func severityToLevel(sev string) string {
    switch sev {
    case "CRITICAL", "HIGH":
        return "error"
    case "MEDIUM":
        return "warning"
    default:
        return "note"
    }
}

func severityToScore(sev string) string {
    switch sev {
    case "CRITICAL":
        return "9.5"
    case "HIGH":
        return "8.5"
    case "MEDIUM":
        return "6.5"
    default:
        return "3.5"
    }
}

func (r *Reporter) ExportSARIF(outputPath string, vulns []scanner.Vulnerability) error {
    // Benzersiz kural tiplerini topla
    ruleTypes := make([]string, 0)
    seen := map[string]bool{}
    for _, v := range vulns {
        if !seen[v.Type] {
            seen[v.Type] = true
            ruleTypes = append(ruleTypes, v.Type)
        }
    }

    rules := make([]sarifRule, 0, len(ruleTypes))
    for _, t := range ruleTypes {
        sev := "MEDIUM"
        score := 0.70
        for _, v := range vulns {
            if v.Type == t {
                sev = v.Severity
                score = v.Score
                break
            }
        }
        rules = append(rules, sarifRule{
            ID:   t,
            Name: t,
            ShortDescription: map[string]string{
                "text": fmt.Sprintf("%s vulnerability detected by ShieldGuard", t),
            },
            DefaultConfiguration: map[string]string{
                "level": severityToLevel(sev),
            },
            Properties: map[string]string{
                "security-severity": severityToScore(sev),
                "score":             fmt.Sprintf("%.2f", score),
            },
        })
    }

    results := make([]sarifResult, 0, len(vulns))
    for _, v := range vulns {
        results = append(results, sarifResult{
            RuleID: v.Type,
            Level:  severityToLevel(v.Severity),
            Message: map[string]string{
                "text": fmt.Sprintf("%s vulnerability found on line %d (severity: %s)", v.Type, v.Line, v.Severity),
            },
            Locations: []sarifLocation{
                {
                    PhysicalLocation: sarifPhysicalLocation{
                        ArtifactLocation: sarifArtifactLocation{
                            URI: filepath.ToSlash(v.FilePath),
                        },
                        Region: sarifRegion{
                            StartLine: v.Line,
                            Snippet:   map[string]string{"text": v.Snippet},
                        },
                    },
                },
            },
        })
    }

    doc := sarifDocument{
        Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        Version: "2.1.0",
        Runs: []sarifRun{
            {
                Tool: sarifTool{
                    Driver: sarifDriver{
                        Name:           "ShieldGuard",
                        Version:        "2.0.0",
                        InformationURI: "https://github.com/Qyroxen/shieldguard",
                        Rules:          rules,
                    },
                },
                Results: results,
            },
        },
    }

    data, err := json.MarshalIndent(doc, "", "  ")
    if err != nil {
        return err
    }
    return os.WriteFile(outputPath, data, 0644)
}

func (r *Reporter) ExportHTML(outputPath string, vulns []scanner.Vulnerability) error {
    html := `<!DOCTYPE html>
<html>
<head>
    <title>ShieldGuard Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f4f6f9; color: #333; }
        h1 { color: #d9534f; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background: #fff; }
        th, td { padding: 12px; border: 1px solid #ddd; text-align: left; }
        th { background: #343a40; color: #fff; }
        .CRITICAL { color: #d9534f; font-weight: bold; }
        .HIGH { color: #f0ad4e; font-weight: bold; }
        .MEDIUM { color: #5bc0de; font-weight: bold; }
        .LOW { color: #777; font-weight: bold; }
    </style>
</head>
<body>
    <h1>ShieldGuard Security Scan Report</h1>
    <p>Generated by ShieldGuard v2.0.0 (Local-First SAST CLI)</p>
    <table>
        <tr>
            <th>File Path</th>
            <th>Line</th>
            <th>Type</th>
            <th>Severity</th>
            <th>Score</th>
            <th>Snippet</th>
        </tr>`

    for _, v := range vulns {
        html += fmt.Sprintf("<tr><td>%s</td><td>%d</td><td>%s</td><td class=\"%s\">%s</td><td>%.2f</td><td><code>%s</code></td></tr>",
            strings.ReplaceAll(v.FilePath, "<", "&lt;"),
            v.Line, v.Type, v.Severity, v.Severity, v.Score,
            strings.ReplaceAll(v.Snippet, "<", "&lt;"))
    }

    html += `
    </table>
</body>
</html>`

    return os.WriteFile(outputPath, []byte(html), 0644)
}
