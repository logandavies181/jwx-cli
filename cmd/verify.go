package cmd

import (
	//	"fmt"

	"github.com/spf13/cobra"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a jwt",
	Run: func(cmd *cobra.Command, args []string) {
		jwtVerifyMain()
	},
}

func init() {
	jwtCmd.AddCommand(verifyCmd)
}

func jwtVerifyMain() {
	// TODO: allow private key verification

	if keyFile != "" && jwkFile != "" && jwkURL != "" {
		exit(&jwxCliError{reason: "Can only specify one option from key, file and url"})
	}

	// Note that internalJWK.jwk could be a jwk, or a jwks with one or many entries
	exit(&jwxCliError{reason: "Note implemented"}) // TODO: Generate jwk first
}
