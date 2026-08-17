package report

import (
    "fmt"
    "github.com/fatih/color"
    "github.com/Qyroxen/shieldguard/pkg/scanner"
)

type Reporter struct{}

func NewReporter() *Reporter { return &Reporter{} }

func (r *Reporter) PrintSummary(vs []scanner.Vulnerability) {
    color.New(color.FgYellow).Printf("Found %d vulnerabilities:\n", len(vs))
    for _, v := range vs {
        fmt.Printf("- %s:%d %s (score=%.2f)\n", v.FilePath, v.Line, v.Type, v.Score)
    }
}

func (r *Reporter) PrintVulnerabilityWithFix(v scanner.Vulnerability, analysis, patch string) {
    color.New(color.FgHiRed).Printf("\nVulnerability: %s:%d %s\n", v.FilePath, v.Line, v.Type)
    fmt.Printf("Snippet: %s\nAnalysis: %s\n", v.Snippet, analysis)
}
