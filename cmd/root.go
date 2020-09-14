package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	jwtFile, jwkFile, keyFile string
)

var rootCmd = &cobra.Command{
	Use:           "jwx-cli",
	Short:         "A tool for working with jose technologies on the command line",
	SilenceErrors: true,
	SilenceUsage:  true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// These two commands want the same flags but they don't really need to be global
	jwkCmd.PersistentFlags().StringVarP(&jwtFile, "jwt", "t", "", "JWT file to read from")
	jwkCmd.PersistentFlags().StringVarP(&keyFile, "key", "k", "", "PEM format Key file to read from. Can be public or private key")

	jwtCmd.PersistentFlags().StringVarP(&jwtFile, "jwt", "t", "", "JWT file to read from")
	jwtCmd.PersistentFlags().StringVarP(&jwkFile, "jwk", "w", "", "JWK file to read from")
	jwtCmd.PersistentFlags().StringVarP(&keyFile, "key", "k", "", "PEM format Key file to read from. Can be public or private key")

	rootCmd.AddCommand(jwtCmd)
	rootCmd.AddCommand(jwkCmd)
}

var jwtCmd = &cobra.Command{
	Use:   "jwt",
	Short: "Parent command for jwt specific actions",
}

var jwkCmd = &cobra.Command{
	Use:   "jwk",
	Short: "Parent command for jwk specific actions",
}
