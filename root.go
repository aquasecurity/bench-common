package main

import (
	goflag "flag"
	"fmt"
	"os"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile           string
	jsonFmt           bool
	noRemediations    bool
	includeTestOutput bool
	define            []string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "bench-common",
	Short: "Bench-common is a golang automation to run tests based on a specific format in .yaml files",
	Long: `This tool is used as a sub module in the application Docker-bench. It is also used as a generic test runner.

Giving a yaml file with the bench project format, it will run and print the tests and the result.
For example:
./bench-common --config /home/config.yaml
`,
	Run: app,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.app.yaml)")
	rootCmd.PersistentFlags().StringArrayVar(&define, "define", []string{""}, "")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.PersistentFlags().BoolVar(&jsonFmt, "json", false, "Prints the results as JSON")
	rootCmd.PersistentFlags().BoolVar(&noRemediations, "noremediations", false, "Disable printing of remediations section")
	rootCmd.PersistentFlags().BoolVar(&includeTestOutput, "include-test-output", false, "Prints the test's output")

	goflag.CommandLine.VisitAll(func(goflag *goflag.Flag) {
		rootCmd.PersistentFlags().AddGoFlag(goflag)
	})
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".app" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".app")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	// If the json flag is on, don't print the message because the output should be only in json format
	if err := viper.ReadInConfig(); err == nil && !jsonFmt {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
