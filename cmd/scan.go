package cmd

import (
    "context"
    "fmt"
    "path/filepath"
    "sync"
    "time"

    "github.com/fatih/color"
    "github.com/spf13/cobra"
    "github.com/spf13/viper"

    "github.com/Qyroxen/shieldguard/pkg/ollama"
    "github.com/Qyroxen/shieldguard/pkg/patch"
    "github.com/Qyroxen/shieldguard/pkg/report"
    "github.com/Qyroxen/shieldguard/pkg/scanner"
)

var scanPath string
var modelName string
var autoFix bool
var ollamaURL string
var concurrency int
var timeoutSec int

func init() {
    scanCmd.Flags().StringVar(&scanPath, "path", ".", "Taranacak proje dizini")
    scanCmd.Flags().StringVar(&modelName, "model", "", "Kullanilacak Ollama modeli")
    scanCmd.Flags().StringVar(&ollamaURL, "ollama-url", "", "Ollama base URL")
    scanCmd.Flags().BoolVar(&autoFix, "auto-fix", false, "Yamalari otomatik uygula")
    scanCmd.Flags().IntVar(&concurrency, "concurrency", 0, "Eszamanli LLM analiz worker sayisi")
    scanCmd.Flags().IntVar(&timeoutSec, "timeout", 0, "Toplam analiz zaman asimi (saniye)")

    rootCmd.AddCommand(scanCmd)
}

func resolveConfig(cmd *cobra.Command) {
    if cmd.Flags().Changed("model") {
        // CLI bayrağı öncelikli
    } else if viper.IsSet("model") {
        modelName = viper.GetString("model")
    } else {
        modelName = "llama3"
    }

    if cmd.Flags().Changed("ollama-url") {
    } else if viper.IsSet("ollama_url") {
        ollamaURL = viper.GetString("ollama_url")
    } else {
        ollamaURL = "http://localhost:11434"
    }

    if cmd.Flags().Changed("auto-fix") {
    } else if viper.IsSet("auto_fix") {
        autoFix = viper.GetBool("auto_fix")
    }

    if cmd.Flags().Changed("concurrency") {
    } else if viper.IsSet("concurrency") {
        concurrency = viper.GetInt("concurrency")
    } else {
        concurrency = 3
    }

    if cmd.Flags().Changed("timeout") {
    } else if viper.IsSet("timeout") {
        timeoutSec = viper.GetInt("timeout")
    } else {
        timeoutSec = 120
    }
}

var scanCmd = &cobra.Command{
    Use:   "scan",
    Short: "Kod tabanini tarar ve olasi guvenlik aciklarini raporlar",
    Run: func(cmd *cobra.Command, args []string) {
        resolveConfig(cmd)

        if viper.ConfigFileUsed() != "" {
            color.New(color.FgCyan).Printf("Konfigürasyon yuklendi: %s\n", viper.ConfigFileUsed())
        }

        color.New(color.FgGreen).Printf("Scan baslatiliyor: %s (model=%s, workers=%d) auto-fix=%v\n", scanPath, modelName, concurrency, autoFix)

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

        if autoFix && !patch.IsWorkTreeClean() {
            color.New(color.FgYellow).Println("[!] UYARI: Git calisma dizini temiz degil. Degisikliklerinizi kaydetmeniz onerilir.")
        }

        client := ollama.NewClient(ollamaURL, modelName)

        jobs := make(chan scanner.Vulnerability, len(vulns))
        results := make(chan error, len(vulns))

        ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
        defer cancel()

        var wg sync.WaitGroup

        for i := 0; i < concurrency; i++ {
            wg.Add(1)
            go func() {
                defer wg.Done()
                for v := range jobs {
                    select {
                    case <-ctx.Done():
                        results <- ctx.Err()
                        return
                    default:
                    }

                    color.New(color.FgYellow).Printf("\n[+] Analiz ediliyor: %s:%d (%s)\n", v.FilePath, v.Line, v.Type)
                    analysis, patchText, err := client.AnalyzeAndFix(v)
                    if err != nil {
                        color.New(color.FgRed).Printf("LLM hatasi (%s:%d): %v\n", v.FilePath, v.Line, err)
                        results <- err
                        continue
                    }

                    reporter.PrintVulnerabilityWithFix(v, analysis, patchText)

                    if autoFix && patchText != "" {
                        err := patch.ApplyLineFix(v.FilePath, v.Line, patchText)
                        if err != nil {
                            color.New(color.FgRed).Printf("Yama uygulanamadi: %v\n", err)
                            results <- err
                        } else {
                            color.New(color.FgCyan).Printf("=> [AUTO-FIX] %s:%d basariyla duzeltildi!\n", v.FilePath, v.Line)
                            results <- nil
                        }
                    } else {
                        results <- nil
                    }
                }
            }()
        }

        for _, v := range vulns {
            jobs <- v
        }
        close(jobs)

        wg.Wait()
        close(results)

        fmt.Println("\nScan tamamlandi.")
    },
}