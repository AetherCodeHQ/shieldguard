package cmd

import (
    "fmt"
    "path/filepath"

    "github.com/fatih/color"
    "github.com/spf13/cobra"

    "github.com/Qyroxen/shieldguard/pkg/ollama"
    "github.com/Qyroxen/shieldguard/pkg/patch"
    "github.com/Qyroxen/shieldguard/pkg/report"
    "github.com/Qyroxen/shieldguard/pkg/scanner"
)

var scanPath string
var modelName string
var autoFix bool
var ollamaURL string

func init() {
    scanCmd.Flags().StringVar(&scanPath, "path", ".", "Taranacak proje dizini")
    scanCmd.Flags().StringVar(&modelName, "model", "llama3", "Kullanilacak Ollama modeli")
    scanCmd.Flags().StringVar(&ollamaURL, "ollama-url", "http://localhost:11434", "Ollama base URL")
    scanCmd.Flags().BoolVar(&autoFix, "auto-fix", false, "Onay sonrasi yamalari otomatik uygula")
    rootCmd.AddCommand(scanCmd)
}

var scanCmd = &cobra.Command{
    Use:   "scan",
    Short: "Kod tabanini tarar ve olasi guvenlik aciklarini raporlar",
    Run: func(cmd *cobra.Command, args []string) {
        color.New(color.FgGreen).Printf("Scan baslatiliyor: %s (model=%s) auto-fix=%v\n", scanPath, modelName, autoFix)

        absPath, _ := filepath.Abs(scanPath)
        reporter := report.NewReporter()
        sc := scanner.NewScanner(absPath)

        vulns, err := sc.Scan()
        if err != nil {
            color.New(color.FgRed).Printf("Scanner hatasi: %v\n", err)
            return
        }
        reporter.PrintSummary(vulns)
        if len(vulns) == 0 {
            return
        }

        client := ollama.NewClient(ollamaURL, modelName)
        for _, v := range vulns {
            color.New(color.FgYellow).Printf("\n[+] Analiz ediliyor: %s:%d (%s)\n", v.FilePath, v.Line, v.Type)
            analysis, patchText, err := client.AnalyzeAndFix(v)
            if err != nil {
                color.New(color.FgRed).Printf("LLM hatasi: %v\n", err)
                continue
            }
            reporter.PrintVulnerabilityWithFix(v, analysis, patchText)

            if autoFix && patchText != "" {
                err := patch.ApplyLineFix(v.FilePath, v.Line, patchText)
                if err != nil {
                    color.New(color.FgRed).Printf("Yama uygulanamadi: %v\n", err)
                } else {
                    color.New(color.FgCyan).Printf("=> [AUTO-FIX] %s:%d başarıyla düzeltildi!\n", v.FilePath, v.Line)
                }
            }
        }
        fmt.Println("\nScan tamamlandi.")
    },
}
