package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var (
	cfgFile string

	keyFile    string
	keyLen     int
	outputFile string
	decode     bool

	jwkFile string
	jwkURL  string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "jwx-cli",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
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
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.jwx-cli.yaml)")

	// our flags here
	rootCmd.PersistentFlags().StringVarP(&keyFile, "key", "k", "", "Key for signing. Only valid with --sign")
	rootCmd.PersistentFlags().IntVarP(&keyLen, "len", "l", 2048, "Key length if key is being generated. Only valid with --sign")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "out", "o", "", "File to output to. Default STDOUT")
	rootCmd.PersistentFlags().BoolVarP(&decode, "decode", "d", false, "Decode printed JWTs. Default false")

	rootCmd.Flags().StringVarP(&jwkFile, "file", "f", "", "Filename to read JWK from")
	rootCmd.Flags().StringVarP(&jwkURL, "url", "u", "", "HTTP address to read JWK from")
	//verifyCmd.Flags().BoolVarP(&isJWKS, "jwks", "", false, "Whether the retrieved JWK is a JWKS")

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

		// Search config in home directory with name ".jwx-cli" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".jwx-cli")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
