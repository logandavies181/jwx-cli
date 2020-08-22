package cmd

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/spf13/cobra"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a jwt from a file using a key or jwk",
	RunE:  jwtVerify,
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}

func jwtVerify(_ *cobra.Command, _ []string) error {
	if jwtFile == "" {
		return errors.New("You must supply a jwt file")
	}

	jwtToVerify, err := ioutil.ReadFile(jwtFile)
	if err != nil {
		return err
	}

	// Prefer jwkFile over keyFile
	if jwkFile != "" {
		jwkFd, err := os.Open(jwkFile)
		if err != nil {
			return err
		}
		jwkSet, err := jwk.Parse(jwkFd)
		if err != nil {
			return err
		}
		// TODO: loop over full set of keys
		_, err = jws.VerifyWithJWK(jwtToVerify, jwkSet.Keys[0])
		if err != nil {
			return err
		}
		fmt.Println("success")
	}

	if keyFile != "" {
		fmt.Println("todo!")
	}
	return nil
}
