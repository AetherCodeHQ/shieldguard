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
var reportFormat string
var outputPath string

func init() {
    scanCmd.Flags().StringVar(&scanPath, "path", ".", "Target project directory to scan")
    scanCmd.Flags().StringVar(&modelName, "model", "", "Ollama model name to use")
    scanCmd.Flags().StringVar(&ollamaURL, "ollama-url", "", "Ollama base URL")
    scanCmd.Flags().BoolVar(&autoFix, "auto-fix", false, "Automatically apply LLM code patches")
    scanCmd.Flags().IntVar(&concurrency, "concurrency", 0, "Number of concurrent LLM workers")
    scanCmd.Flags().IntVar(&timeoutSec, "timeout", 0, "Total scan timeout in seconds")
    scanCmd.Flags().StringVar(&reportFormat, "format", "", "Export report format (json or html)")
    scanCmd.Flags().StringVar(&outputPath, "output", "shieldguard-report", "Output filename for the report")

    rootCmd.AddCommand(scanCmd)
}

func resolveConfig(cmd *cobra.Command) {
    if !cmd.Flags().Changed("model") {
        if viper.IsSet("model") {
            modelName = viper.GetString("model")
        } else {
            modelName = "llama3"
        }
    }

    if !cmd.Flags().Changed("ollama-url") {
        if viper.IsSet("ollama_url") {
            ollamaURL = viper.GetString("ollama_url")
        } else {
            ollamaURL = "http://localhost:11434"
        }
    }

    if !cmd.Flags().Changed("auto-fix") && viper.IsSet("auto_fix") {
        autoFix = viper.GetBool("auto_fix")
    }

    if !cmd.Flags().Changed("concurrency") {
        if viper.IsSet("concurrency") {
            concurrency = viper.GetInt("concurrency")
        } else {
            concurrency = 3
        }
    }

    if !cmd.Flags().Changed("timeout") {
        if viper.IsSet("timeout") {
            timeoutSec = viper.GetInt("timeout")
        } else {
            timeoutSec = 120
        }
    }
}

var scanCmd = &cobra.Command{
    Use:   "scan",
    Short: "Scans the codebase for security vulnerabilities and remediates them via local LLMs",
    Run: func(cmd *cobra.Command, args []string) {
        resolveConfig(cmd)

        if viper.ConfigFileUsed() != "" {
            color.New(color.FgCyan).Printf("Loaded configuration file: %s\n", viper.ConfigFileUsed())
        }

        color.New(color.FgGreen).Printf("Starting scan v1.0.1: %s (model=%s, workers=%d, auto-fix=%v)\n", scanPath, modelName, concurrency, autoFix)

        absPath, _ := filepath.Abs(scanPath)
        reporter := report.NewReporter()
        sc := scanner.NewScanner(absPath)

        vulns, err := sc.Scan()
        if err != nil {
            color.New(color.FgRed).Printf("Scanner error: %v\n", err)
            return
        }
        reporter.PrintSummary(vulns)

        // Export report if format specified
        if reportFormat == "json" {
            out := outputPath + ".json"
            _ = reporter.ExportJSON(out, vulns)
            color.New(color.FgCyan).Printf("[+] JSON report exported to: %s\n", out)
        } else if reportFormat == "html" {
            out := outputPath + ".html"
            _ = reporter.ExportHTML(out, vulns)
            color.New(color.FgCyan).Printf("[+] HTML report exported to: %s\n", out)
        }

        if len(vulns) == 0 {
            return
        }

        if autoFix && !patch.IsWorkTreeClean() {
            color.New(color.FgYellow).Println("[!] WARNING: Git working tree is not clean. Stashing or committing uncommitted changes is recommended.")
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

                    color.New(color.FgYellow).Printf("\n[+] Analyzing: %s:%d (%s)\n", v.FilePath, v.Line, v.Type)
                    analysis, patchText, err := client.AnalyzeAndFix(v)
                    if err != nil {
                        color.New(color.FgRed).Printf("LLM error (%s:%d): %v\n", v.FilePath, v.Line, err)
                        results <- err
                        continue
                    }

                    reporter.PrintVulnerabilityWithFix(v, analysis, patchText)

                    if autoFix && patchText != "" {
                        err := patch.ApplyLineFix(v.FilePath, v.Line, patchText)
                        if err != nil {
                            color.New(color.FgRed).Printf("Failed to apply patch: %v\n", err)
                            results <- err
                        } else {
                            color.New(color.FgCyan).Printf("=> [AUTO-FIX] Successfully remediated %s:%d!\n", v.FilePath, v.Line)
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

        fmt.Println("\nScan completed.")
    },
}