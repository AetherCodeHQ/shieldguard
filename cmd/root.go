package cmd

import (
    "fmt"
    "os"

    "github.com/spf13/cobra"
    "github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
    Use:   "shieldguard",
    Short:   "ShieldGuard local-first SAST CLI tool",
    Version: Version,
}

func Execute() {
    if err := rootCmd.Execute(); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}

func init() {
    cobra.OnInitialize(initConfig)
    rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "Path to the configuration file (default: .shieldguard.yaml)")
}

func initConfig() {
    if cfgFile != "" {
        viper.SetConfigFile(cfgFile)
    } else {
        viper.AddConfigPath(".")
        viper.SetConfigType("yaml")
        viper.SetConfigName(".shieldguard")
    }

    viper.AutomaticEnv()

    if err := viper.ReadInConfig(); err == nil {
        // Configuration file loaded successfully
    }
}
