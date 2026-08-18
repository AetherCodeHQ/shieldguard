package scanner

import (
    "go/parser"
    "go/token"
    "os"
    "path/filepath"
    "testing"
)

func TestScanner_Scan(t *testing.T) {
    // Geçici bir test dizini ve dosyası oluşturuyoruz
    tempDir, err := os.MkdirTemp("", "shieldguard_test_*")
    if err != nil {
        t.Fatalf("Gecici dizin olusturulamadi: %v", err)
    }
    defer os.RemoveAll(tempDir)

    mockCode := `package main

import "os/exec"

func main() {
    var apiKey = "SECRET_123456"
    exec.Command("sh", "-c", "ls")
}
`
    testFilePath := filepath.Join(tempDir, "vulnerable.go")
    if err := os.WriteFile(testFilePath, []byte(mockCode), 0644); err != nil {
        t.Fatalf("Test dosyasi yazilamadi: %v", err)
    }

    sc := NewScanner(tempDir)
    vulns, err := sc.Scan()
    if err != nil {
        t.Fatalf("Scan sirasinda hata olustu: %v", err)
    }

    if len(vulns) != 2 {
        t.Fatalf("Beklenen zafiyet sayisi 2, bulunan: %d", len(vulns))
    }

    hasSecret := false
    hasCmd := false

    for _, v := range vulns {
        if v.Type == "HardcodedSecret" {
            hasSecret = true
        }
        if v.Type == "CommandInjection" {
            hasCmd = true
        }
    }

    if !hasSecret || !hasCmd {
        t.Errorf("HardcodedSecret veya CommandInjection zafiyeti tespit edilemedi")
    }
}

func TestExtractSnippetFromPos(t *testing.T) {
    tempFile, err := os.CreateTemp("", "snippet_test_*.go")
    if err != nil {
        t.Fatalf("Gecici dosya olusturulamadi: %v", err)
    }
    defer os.Remove(tempFile.Name())

    content := "package main\n\nfunc hello() {\n\tprintln(\"world\")\n}\n"
    if _, err := tempFile.WriteString(content); err != nil {
        t.Fatalf("Icerik yazilamadi: %v", err)
    }
    tempFile.Close()

    fset := token.NewFileSet()
    node, err := parser.ParseFile(fset, tempFile.Name(), content, 0)
    if err != nil {
        t.Fatalf("AST parse hatasi: %v", err)
    }

    snippet := ExtractSnippetFromPos(tempFile.Name(), node.Pos(), node.End(), fset)
    if snippet == "" {
        t.Errorf("Snippet bos döndü, AST pozisyon extraction basarisiz")
    }
}

func TestScanner_MultiLanguage(t *testing.T) {
    tempDir, err := os.MkdirTemp("", "shieldguard_ml_*")
    if err != nil {
        t.Fatalf("Gecici dizin olusturulamadi: %v", err)
    }
    defer os.RemoveAll(tempDir)

    files := map[string]string{
        "app.py": `import os
import subprocess

def run(cmd):
    os.system(cmd)
    result = subprocess.run(cmd, shell=True)
`,
        "app.js": `function render(user) {
    document.getElementById("out").innerHTML = user.name;
    const resp = await fetch("https://api/" + req.query.url);
}
`,
        "app.java": `class App {
    void run(String cmd) {
        Runtime.getRuntime().exec(cmd);
    }
}
`,
        "app.php": `<?php
$x = unserialize($_POST["data"]);
echo $_GET["q"];
`,
        "clean.go": `package main

// password = "bu bir yorum - raporlanmamali"
func main() {
    _ = 1
}
`,
    }

    for name, content := range files {
        if err := os.WriteFile(filepath.Join(tempDir, name), []byte(content), 0644); err != nil {
            t.Fatalf("Test dosyasi yazilamadi %s: %v", name, err)
        }
    }

    sc := NewScanner(tempDir)
    vulns, err := sc.Scan()
    if err != nil {
        t.Fatalf("Scan sirasinda hata: %v", err)
    }

    got := map[string]bool{}
    for _, v := range vulns {
        got[v.Type] = true
    }

    checks := []struct {
        typ      string
        wantHit  bool
    }{
        {"CommandInjection", true},        // python
        {"XSS", true},                     // js + php
        {"SSRF", true},                    // js
        {"UnsafeDeserialization", true},   // php
        {"HardcodedSecret", false},        // sadece yorum satiri vardi
    }

    for _, c := range checks {
        if got[c.typ] != c.wantHit {
            t.Errorf("Tip %s: beklenen hit=%v, bulunan=%v (vulns: %+v)", c.typ, c.wantHit, got[c.typ], vulns)
        }
    }

    // Java CommandInjection da bulunmali
    if !got["CommandInjection"] {
        t.Errorf("Java Runtime.exec tespit edilemedi")
    }
}

func TestScanner_CommentSkipped(t *testing.T) {
    tempDir, err := os.MkdirTemp("", "shieldguard_cm_*")
    if err != nil {
        t.Fatalf("Gecici dizin olusturulamadi: %v", err)
    }
    defer os.RemoveAll(tempDir)

    mock := `package main

// password = "sadece yorum"
// api_key = "gizli" - go yorumu, raporlanmamali
func main() {
    _ = 1
}
`
    if err := os.WriteFile(filepath.Join(tempDir, "yorum.go"), []byte(mock), 0644); err != nil {
        t.Fatalf("Dosya yazilamadi: %v", err)
    }

    sc := NewScanner(tempDir)
    vulns, err := sc.Scan()
    if err != nil {
        t.Fatalf("Scan hatasi: %v", err)
    }
    if len(vulns) != 0 {
        t.Errorf("Yorum satirlari raporlanmamali, bulunan: %+v", vulns)
    }
}
