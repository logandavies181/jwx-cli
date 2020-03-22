package cmd

import (
	"fmt"

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

var (
	jwkFile string
	jwkURL string
	//isJWKS bool
)

func init() {
	jwtCmd.AddCommand(verifyCmd)

        verifyCmd.Flags().StringVarP(&jwkFile, "file", "f", "", "Filename to read JWK from")
        verifyCmd.Flags().StringVarP(&jwkURL, "url", "u", "", "HTTP address to read JWK from")
        //verifyCmd.Flags().BoolVarP(&isJWKS, "jwks", "", false, "Whether the retrieved JWK is a JWKS")
}

func jwtVerifyMain() {
	// TODO: allow private key verification

	if keyFile != "" && jwkFile != "" && jwkURL != "" {
		exit(&jwxCliError{reason: "Can only specify one option from key, file and url"})
	}

	// Note that internalJWK.jwk could be a jwk, or a jwks with one or many entries
	exit(&jwxCliError{reason: "Note implemented"}) // TODO: Generate jwk first
}
