package cmd

import (
	"fmt"
	"os"
	"io/ioutil"

	"github.com/spf13/cobra"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
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

	if jwtFile == "" {
		exit(&jwxCliError{reason: "You must specify a JWT in a file to verify"})
	}

	jwtToVerify, err := ioutil.ReadFile(jwtFile)
	if err != nil {
		exit(err)
	}

	if jwkFile != "" {
		jwkDat, err := os.Open(jwkFile)
		if err != nil {
			exit (err)
		}
		jwkSet, err := jwk.Parse(jwkDat)
		if err != nil {
			exit (err)
		}
		//jwk1 := *jwkSet
		_, err = jws.VerifyWithJWK(jwtToVerify, jwkSet.Keys[0])
		if err != nil {
			exit (err)
		}
		fmt.Println("success")
	}

	// Note that internalJWK.jwk could be a jwk, or a jwks with one or many entries

}
