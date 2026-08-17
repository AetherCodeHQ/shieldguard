package scanner

import (
    "bufio"
    "errors"
    "os"
    "path/filepath"
    "regexp"
    "strings"
)

type Vulnerability struct {
    FilePath string
    Line     int
    Type     string
    Score    float64
    Snippet  string
}

type Scanner struct {
    Root  string
    rules []rule
}

type rule struct {
    Name    string
    Pattern *regexp.Regexp
    Score   float64
}

func NewScanner(root string) *Scanner {
    rules := []rule{
        {Name: "HardcodedSecret", Pattern: regexp.MustCompile(`(?i)(api[_-]?key|secret|password)\s*[:=]\s*["']?[A-Za-z0-9\-_]{8,}["']?`), Score: 0.95},
        {Name: "CommandInjection", Pattern: regexp.MustCompile(`(?i)(exec\.Command|system\(|popen\()`), Score: 0.8},
        {Name: "SQLConcat", Pattern: regexp.MustCompile(`(?i)(SELECT|INSERT|UPDATE|DELETE).*\+.*`), Score: 0.7},
    }
    return &Scanner{Root: root, rules: rules}
}

func (s *Scanner) Scan() ([]Vulnerability, error) {
    if s.Root == "" {
        return nil, errors.New("root path empty")
    }
    var vulns []Vulnerability
    err := filepath.WalkDir(s.Root, func(path string, d os.DirEntry, err error) error {
        if err != nil || d.IsDir() {
            return nil
        }
        f, err := os.Open(path)
        if err != nil {
            return nil
        }
        defer f.Close()
        sc := bufio.NewScanner(f)
        lineNo := 0
        for sc.Scan() {
            lineNo++
            line := sc.Text()
            for _, r := range s.rules {
                if r.Pattern.MatchString(line) {
                    vulns = append(vulns, Vulnerability{
                        FilePath: path,
                        Line:     lineNo,
                        Type:     r.Name,
                        Score:    r.Score,
                        Snippet:  strings.TrimSpace(line),
                    })
                }
            }
        }
        return nil
    })
    return vulns, err
}
