package scanner

import (
    "bufio"
    "go/token"
    "os"
    "path/filepath"
    "strings"
)

type Vulnerability struct {
    FilePath string
    Line     int
    Type     string
    Severity string
    Score    float64
    Snippet  string
}

type Scanner struct {
    targetDir string
}

func NewScanner(targetDir string) *Scanner {
    return &Scanner{targetDir: targetDir}
}

func (s *Scanner) Scan() ([]Vulnerability, error) {
    var vulns []Vulnerability

    err := filepath.Walk(s.targetDir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }

        if info.IsDir() && (info.Name() == ".git" || info.Name() == "vendor" || info.Name() == "node_modules") {
            return filepath.SkipDir
        }

        if !info.IsDir() && strings.HasSuffix(info.Name(), ".go") {
            fileVulns, err := scanFile(path)
            if err == nil {
                vulns = append(vulns, fileVulns...)
            }
        }

        return nil
    })

    return vulns, err
}

func scanFile(filePath string) ([]Vulnerability, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var vulns []Vulnerability
    scanner := bufio.NewScanner(file)
    lineNum := 0

    for scanner.Scan() {
        lineNum++
        line := scanner.Text()

        if strings.Contains(line, "api_key") || strings.Contains(line, "password") || strings.Contains(line, "SECRET_") {
            vulns = append(vulns, Vulnerability{
                FilePath: filePath,
                Line:     lineNum,
                Type:     "HardcodedSecret",
                Severity: "HIGH",
                Score:    0.95,
                Snippet:  strings.TrimSpace(line),
            })
        }

        if strings.Contains(line, "exec.Command") && (strings.Contains(line, "sh") || strings.Contains(line, "bash") || strings.Contains(line, "cmd")) {
            vulns = append(vulns, Vulnerability{
                FilePath: filePath,
                Line:     lineNum,
                Type:     "CommandInjection",
                Severity: "CRITICAL",
                Score:    0.90,
                Snippet:  strings.TrimSpace(line),
            })
        }

        if strings.Contains(line, "DB.Query") || strings.Contains(line, "Exec(") && (strings.Contains(line, "+") || strings.Contains(line, "fmt.Sprintf")) {
            vulns = append(vulns, Vulnerability{
                FilePath: filePath,
                Line:     lineNum,
                Type:     "SQLInjection",
                Severity: "CRITICAL",
                Score:    0.92,
                Snippet:  strings.TrimSpace(line),
            })
        }

        if strings.Contains(line, "os.Open(") && strings.Contains(line, "r.URL.Query") {
            vulns = append(vulns, Vulnerability{
                FilePath: filePath,
                Line:     lineNum,
                Type:     "PathTraversal",
                Severity: "HIGH",
                Score:    0.85,
                Snippet:  strings.TrimSpace(line),
            })
        }
    }

    return vulns, scanner.Err()
}

func ExtractSnippetFromPos(filePath string, start, end token.Pos, fset *token.FileSet) string {
    return ExtractSnippetSimple(filePath, 1)
}

func ExtractSnippetSimple(filePath string, lineNo int) string {
    file, err := os.Open(filePath)
    if err != nil {
        return ""
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    currentLine := 0
    for scanner.Scan() {
        currentLine++
        if currentLine == lineNo {
            return strings.TrimSpace(scanner.Text())
        }
    }
    return ""
}