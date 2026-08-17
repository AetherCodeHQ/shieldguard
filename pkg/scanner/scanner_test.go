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
