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

// Rule, satir bazinda calisan bir zafiyet tespit kuralidir.
// Exts bos ise kural tum dillerde uygulanir.
type Rule struct {
    Type     string
    Severity string
    Score    float64
    Exts     []string
    Check    func(line string) bool
}

// supportedExts: file extensions that can be scanned.
var supportedExts = map[string]bool{
    ".go": true, ".js": true, ".jsx": true, ".ts": true, ".tsx": true,
    ".py": true, ".java": true, ".php": true, ".rb": true,
    ".c": true, ".h": true, ".cpp": true, ".hpp": true, ".cc": true,
}

// rules: vulnerability rule catalog (v2.0.0 - multi-language).
var rules = []Rule{
    // ---- Tum diller ----
    {
        Type: "HardcodedSecret", Severity: "HIGH", Score: 0.95,
        Check: func(l string) bool {
            return hasSecretKeyword(l) && hasAssignment(l) && hasStringValue(l)
        },
    },
    {
        Type: "WeakCrypto", Severity: "MEDIUM", Score: 0.70,
        Check: func(l string) bool {
            lower := strings.ToLower(l)
            return strings.Contains(lower, "md5") || strings.Contains(lower, "sha1")
        },
    },
    {
        Type: "InsecureRandom", Severity: "MEDIUM", Score: 0.65,
        Check: func(l string) bool {
            lower := strings.ToLower(l)
            return strings.Contains(lower, "math/rand") ||
                strings.Contains(lower, "random.random") ||
                strings.Contains(lower, "random.randint") ||
                strings.Contains(lower, "java.util.random") ||
                strings.Contains(lower, "rand(") ||
                strings.Contains(lower, "mt_rand")
        },
    },
    // ---- Go ----
    {
        Type: "CommandInjection", Severity: "CRITICAL", Score: 0.90, Exts: []string{".go"},
        Check: func(l string) bool {
            // Shell names must be quoted strings (avoids flagging a variable named cmd)
            return strings.Contains(l, "exec.Command") &&
                (strings.Contains(l, "\"sh\"") || strings.Contains(l, "\"bash\"") || strings.Contains(l, "\"cmd\""))
        },
    },
    {
        Type: "SQLInjection", Severity: "CRITICAL", Score: 0.92, Exts: []string{".go"},
        Check: func(l string) bool {
            return (strings.Contains(l, "DB.Query") || strings.Contains(l, ".Query(") || strings.Contains(l, ".Exec(")) &&
                (strings.Contains(l, "+") || strings.Contains(l, "fmt.Sprintf"))
        },
    },
    {
        Type: "PathTraversal", Severity: "HIGH", Score: 0.85, Exts: []string{".go"},
        Check: func(l string) bool {
            return strings.Contains(l, "os.Open(") && strings.Contains(l, "r.URL.Query")
        },
    },
    {
        Type: "SSRF", Severity: "HIGH", Score: 0.88, Exts: []string{".go"},
        Check: func(l string) bool {
            return (strings.Contains(l, "http.Get") || strings.Contains(l, "http.Post") || strings.Contains(l, "http.NewRequest")) &&
                (strings.Contains(l, "r.URL.Query") || strings.Contains(l, "r.FormValue") || strings.Contains(l, "r.Form["))
        },
    },
    {
        Type: "LDAPInjection", Severity: "HIGH", Score: 0.86, Exts: []string{".go"},
        Check: func(l string) bool {
            return strings.Contains(l, "ldap.NewSearchRequest") &&
                (strings.Contains(l, "+") || strings.Contains(l, "fmt.Sprintf"))
        },
    },
    // ---- JavaScript / TypeScript ----
    {
        Type: "CommandInjection", Severity: "CRITICAL", Score: 0.90, Exts: []string{".js", ".jsx", ".ts", ".tsx"},
        Check: func(l string) bool {
            return strings.Contains(l, "child_process") ||
                strings.Contains(l, "execSync") ||
                strings.Contains(l, ".exec(") ||
                strings.Contains(l, ".spawn(")
        },
    },
    {
        Type: "SQLInjection", Severity: "CRITICAL", Score: 0.92, Exts: []string{".js", ".jsx", ".ts", ".tsx"},
        Check: func(l string) bool {
            return (strings.Contains(l, ".query(") || strings.Contains(l, ".execute(") || strings.Contains(l, "sequelize.query")) &&
                (strings.Contains(l, "`") || strings.Contains(l, "+") || strings.Contains(l, "template"))
        },
    },
    {
        Type: "XSS", Severity: "HIGH", Score: 0.85, Exts: []string{".js", ".jsx", ".ts", ".tsx"},
        Check: func(l string) bool {
            return strings.Contains(l, "innerHTML") ||
                strings.Contains(l, "document.write") ||
                strings.Contains(l, "dangerouslySetInnerHTML")
        },
    },
    {
        Type: "SSRF", Severity: "HIGH", Score: 0.88, Exts: []string{".js", ".jsx", ".ts", ".tsx"},
        Check: func(l string) bool {
            return (strings.Contains(l, "fetch(") || strings.Contains(l, "axios.")) &&
                (strings.Contains(l, "req.query") || strings.Contains(l, "req.params") || strings.Contains(l, "req.body"))
        },
    },
    // ---- Python ----
    {
        Type: "CommandInjection", Severity: "CRITICAL", Score: 0.90, Exts: []string{".py"},
        Check: func(l string) bool {
            // os.system/os.popen her zaman shell kullanir - tek basina da zafiyet
            if strings.Contains(l, "os.system") || strings.Contains(l, "os.popen") {
                return true
            }
            // subprocess icin shell=True veya string birlestirme gerekir
            return strings.Contains(l, "subprocess.") &&
                (strings.Contains(l, "shell=True") || strings.Contains(l, "+") || strings.Contains(l, "f\"") || strings.Contains(l, "f'"))
        },
    },
    {
        Type: "CommandInjection", Severity: "CRITICAL", Score: 0.90, Exts: []string{".py"},
        Check: func(l string) bool {
            return strings.Contains(l, "eval(") || strings.Contains(l, "exec(")
        },
    },
    {
        Type: "SQLInjection", Severity: "CRITICAL", Score: 0.92, Exts: []string{".py"},
        Check: func(l string) bool {
            return strings.Contains(l, ".execute(") &&
                (strings.Contains(l, "f\"") || strings.Contains(l, "f'") || strings.Contains(l, "format(") || strings.Contains(l, "%") || strings.Contains(l, "+"))
        },
    },
    {
        Type: "PathTraversal", Severity: "HIGH", Score: 0.85, Exts: []string{".py"},
        Check: func(l string) bool {
            return (strings.Contains(l, "open(") || strings.Contains(l, "send_file")) &&
                (strings.Contains(l, "request.args") || strings.Contains(l, "request.form") || strings.Contains(l, "request.get_json"))
        },
    },
    {
        Type: "SSRF", Severity: "HIGH", Score: 0.88, Exts: []string{".py"},
        Check: func(l string) bool {
            return strings.Contains(l, "requests.") &&
                (strings.Contains(l, "request.args") || strings.Contains(l, "request.form") || strings.Contains(l, "input("))
        },
    },
    {
        Type: "UnsafeDeserialization", Severity: "CRITICAL", Score: 0.94, Exts: []string{".py"},
        Check: func(l string) bool {
            return strings.Contains(l, "pickle.loads") || strings.Contains(l, "yaml.load(") || strings.Contains(l, "marshal.loads")
        },
    },
    // ---- Java ----
    {
        Type: "CommandInjection", Severity: "CRITICAL", Score: 0.90, Exts: []string{".java"},
        Check: func(l string) bool {
            return strings.Contains(l, "Runtime.getRuntime().exec") || strings.Contains(l, "ProcessBuilder")
        },
    },
    {
        Type: "SQLInjection", Severity: "CRITICAL", Score: 0.92, Exts: []string{".java"},
        Check: func(l string) bool {
            return (strings.Contains(l, "createStatement") || strings.Contains(l, ".executeQuery") || strings.Contains(l, ".execute(")) &&
                (strings.Contains(l, "+") || strings.Contains(l, "String.format"))
        },
    },
    {
        Type: "UnsafeDeserialization", Severity: "CRITICAL", Score: 0.94, Exts: []string{".java"},
        Check: func(l string) bool {
            return strings.Contains(l, "ObjectInputStream") && strings.Contains(l, "readObject")
        },
    },
    {
        Type: "SSRF", Severity: "HIGH", Score: 0.88, Exts: []string{".java"},
        Check: func(l string) bool {
            return (strings.Contains(l, "new URL(") || strings.Contains(l, "HttpURLConnection") || strings.Contains(l, "HttpClient")) &&
                strings.Contains(l, "getParameter")
        },
    },
    {
        Type: "LDAPInjection", Severity: "HIGH", Score: 0.86, Exts: []string{".java"},
        Check: func(l string) bool {
            return strings.Contains(l, "DirContext") && strings.Contains(l, "search") && strings.Contains(l, "+")
        },
    },
    // ---- PHP ----
    {
        Type: "CommandInjection", Severity: "CRITICAL", Score: 0.90, Exts: []string{".php"},
        Check: func(l string) bool {
            return (strings.Contains(l, "shell_exec") || strings.Contains(l, "system(") || strings.Contains(l, "exec(") || strings.Contains(l, "passthru")) &&
                (strings.Contains(l, "$_GET") || strings.Contains(l, "$_POST") || strings.Contains(l, "$_REQUEST"))
        },
    },
    {
        Type: "SQLInjection", Severity: "CRITICAL", Score: 0.92, Exts: []string{".php"},
        Check: func(l string) bool {
            return (strings.Contains(l, "mysqli_query") || strings.Contains(l, "mysql_query") || strings.Contains(l, "->query(")) &&
                (strings.Contains(l, "$_GET") || strings.Contains(l, "$_POST") || strings.Contains(l, "$_REQUEST"))
        },
    },
    {
        Type: "XSS", Severity: "HIGH", Score: 0.85, Exts: []string{".php"},
        Check: func(l string) bool {
            return (strings.Contains(l, "echo") || strings.Contains(l, "print")) &&
                (strings.Contains(l, "$_GET") || strings.Contains(l, "$_POST"))
        },
    },
    {
        Type: "UnsafeDeserialization", Severity: "CRITICAL", Score: 0.94, Exts: []string{".php"},
        Check: func(l string) bool {
            return strings.Contains(l, "unserialize(")
        },
    },
    // ---- Ruby ----
    {
        Type: "CommandInjection", Severity: "CRITICAL", Score: 0.90, Exts: []string{".rb"},
        Check: func(l string) bool {
            return (strings.Contains(l, "system(") || strings.Contains(l, "exec(") || strings.Contains(l, "`")) &&
                strings.Contains(l, "params")
        },
    },
    {
        Type: "SQLInjection", Severity: "CRITICAL", Score: 0.92, Exts: []string{".rb"},
        Check: func(l string) bool {
            return strings.Contains(l, ".execute(") || (strings.Contains(l, "find_by_sql") && strings.Contains(l, "+"))
        },
    },
    {
        Type: "UnsafeDeserialization", Severity: "CRITICAL", Score: 0.94, Exts: []string{".rb"},
        Check: func(l string) bool {
            return strings.Contains(l, "Marshal.load")
        },
    },
    // ---- C / C++ ----
    {
        Type: "CommandInjection", Severity: "CRITICAL", Score: 0.90, Exts: []string{".c", ".h", ".cpp", ".hpp", ".cc"},
        Check: func(l string) bool {
            return (strings.Contains(l, "system(") || strings.Contains(l, "popen(") || strings.Contains(l, "execl")) &&
                strings.Contains(l, "argv")
        },
    },
    {
        Type: "SQLInjection", Severity: "CRITICAL", Score: 0.92, Exts: []string{".c", ".h", ".cpp", ".hpp", ".cc"},
        Check: func(l string) bool {
            return (strings.Contains(l, "mysql_query") || strings.Contains(l, "sqlite3_exec")) && strings.Contains(l, "+")
        },
    },
}

type Scanner struct {
    targetDir string
    ignores   []string
}

func NewScanner(targetDir string) *Scanner {
    return &Scanner{
        targetDir: targetDir,
        ignores:   loadIgnores(targetDir),
    }
}

// loadIgnores: reads patterns from the .shieldguardignore file (gitignore style).
func loadIgnores(targetDir string) []string {
    var ignores []string
    ignorePath := filepath.Join(targetDir, ".shieldguardignore")
    data, err := os.ReadFile(ignorePath)
    if err != nil {
        return ignores
    }
    for _, line := range strings.Split(string(data), "\n") {
        line = strings.TrimSpace(line)
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        ignores = append(ignores, line)
    }
    return ignores
}

// isIgnored: does the given file/directory match any ignore pattern?
func (s *Scanner) isIgnored(path string) bool {
    rel, err := filepath.Rel(s.targetDir, path)
    if err != nil {
        return false
    }
    rel = filepath.ToSlash(rel)
    for _, pat := range s.ignores {
        pat = filepath.ToSlash(strings.TrimSuffix(pat, "/"))
        // Exact match (file)
        if rel == pat {
            return true
        }
        // If the pattern is a directory, also match its contents
        if strings.HasPrefix(rel, pat+"/") {
            return true
        }
        // Basit glob (tek segment, ornek: *.test.go)
        if ok, _ := filepath.Match(pat, filepath.Base(rel)); ok {
            return true
        }
    }
    return false
}

func (s *Scanner) Scan() ([]Vulnerability, error) {
    var vulns []Vulnerability

    err := filepath.Walk(s.targetDir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }

        if info.IsDir() {
            if info.Name() == ".git" || info.Name() == "vendor" || info.Name() == "node_modules" || info.Name() == "__pycache__" {
                return filepath.SkipDir
            }
            if s.isIgnored(path) {
                return filepath.SkipDir
            }
            return nil
        }

        if s.isIgnored(path) {
            return nil
        }

        if !info.IsDir() {
            ext := strings.ToLower(filepath.Ext(info.Name()))
            if supportedExts[ext] {
                fileVulns, scanErr := scanFile(path, ext)
                if scanErr == nil {
                    vulns = append(vulns, fileVulns...)
                }
            }
        }

        return nil
    })

    return vulns, err
}

func scanFile(filePath, ext string) ([]Vulnerability, error) {
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

        // Skip comment lines (reduces false positives)
        if isCommentLine(line, ext) {
            continue
        }

        for _, rule := range rules {
            if !ruleApplies(rule, ext) {
                continue
            }
            if rule.Check(line) {
                vulns = append(vulns, Vulnerability{
                    FilePath: filePath,
                    Line:     lineNum,
                    Type:     rule.Type,
                    Severity: rule.Severity,
                    Score:    rule.Score,
                    Snippet:  strings.TrimSpace(line),
                })
            }
        }
    }

    return vulns, scanner.Err()
}

// ruleApplies: does this rule apply to the given file extension?
// Kuralin Exts listesi bos ise tum dillerde uygulanir.
func ruleApplies(rule Rule, ext string) bool {
    if len(rule.Exts) == 0 {
        return true
    }
    for _, e := range rule.Exts {
        if e == ext {
            return true
        }
    }
    return false
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

// isCommentLine: checks whether the line is a comment (per language).
func isCommentLine(line, ext string) bool {
    t := strings.TrimSpace(line)
    switch ext {
    case ".py", ".rb":
        return strings.HasPrefix(t, "#")
    case ".php":
        return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*")
    default:
        return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*")
    }
}

// hasSecretKeyword: sifir/anahtar kelime iceren satir mi?
func hasSecretKeyword(line string) bool {
    lower := strings.ToLower(line)
    return strings.Contains(lower, "api_key") ||
        strings.Contains(lower, "apikey") ||
        strings.Contains(lower, "password") ||
        strings.Contains(lower, "passwd") ||
        strings.Contains(lower, "secret") ||
        strings.Contains(line, "SECRET_") ||
        strings.Contains(lower, "token")
}

// hasAssignment: does the line contain an assignment operator?
func hasAssignment(line string) bool {
    return strings.Contains(line, "=") || strings.Contains(line, ":=")
}

// hasStringValue: satirda tirnakli bir string deger var mi?
func hasStringValue(line string) bool {
    return strings.Contains(line, "\"") || strings.Contains(line, "`")
}
