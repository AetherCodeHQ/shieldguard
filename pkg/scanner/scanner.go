package scanner

import (
    "bufio"
    "bytes"
    "go/token"
    "os"
    "path/filepath"
    "regexp"
    "strings"
)

type Vulnerability struct {
    FilePath string  `json:"file_path"`
    Line     int     `json:"line"`
    Type     string  `json:"type"`
    Score    float64 `json:"score"`
    Snippet  string  `json:"snippet"`
}

type Scanner struct {
    RootPath string
}

func NewScanner(root string) *Scanner {
    return &Scanner{RootPath: root}
}

func ExtractSnippetFromPos(path string, start token.Pos, end token.Pos, fset *token.FileSet) string {
    file := fset.File(start)
    if file == nil {
        return ""
    }
    startLine := file.Line(start)
    endLine := file.Line(end)

    data, err := os.ReadFile(path)
    if err != nil {
        return ""
    }
    lines := bytes.Split(data, []byte("\n"))

    if startLine <= 0 {
        startLine = 1
    }
    if endLine > len(lines) {
        endLine = len(lines)
    }

    return string(bytes.Join(lines[startLine-1:endLine], []byte("\n")))
}

func (s *Scanner) Scan() ([]Vulnerability, error) {
    var vulns []Vulnerability

    secretRegex := regexp.MustCompile(`(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*["']([^"']+)["']`)
    cmdRegex := regexp.MustCompile(`exec\.Command\(["'](sh|bash|cmd)["']`)

    err := filepath.Walk(s.RootPath, func(path string, info os.FileInfo, err error) error {
        if err != nil || info.IsDir() {
            return nil
        }

        if strings.HasSuffix(path, ".go") {
            file, err := os.Open(path)
            if err != nil {
                return nil
            }
            defer file.Close()

            sc := bufio.NewScanner(file)
            lineNo := 0
            for sc.Scan() {
                lineNo++
                line := sc.Text()

                if secretRegex.MatchString(line) {
                    vulns = append(vulns, Vulnerability{
                        FilePath: path,
                        Line:     lineNo,
                        Type:     "HardcodedSecret",
                        Score:    0.95,
                        Snippet:  strings.TrimSpace(line),
                    })
                }

                if cmdRegex.MatchString(line) {
                    vulns = append(vulns, Vulnerability{
                        FilePath: path,
                        Line:     lineNo,
                        Type:     "CommandInjection",
                        Score:    0.80,
                        Snippet:  strings.TrimSpace(line),
                    })
                }
            }
        }
        return nil
    })

    return vulns, err
}
