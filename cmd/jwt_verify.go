package cmd

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/lestrrat-go/jwx/jwa"
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
	jwtCmd.AddCommand(verifyCmd)
}

func jwtVerify(_ *cobra.Command, _ []string) error {
	if jwtFile == "" {
		return errors.New("You must supply a jwt file")
	}

	jwtToVerify, err := ioutil.ReadFile(jwtFile)
	if err != nil {
		return err
	}

	// TODO: add options for additional verification i.e. exp, sub, claims, etc
	// at the moment it's only signature verification and the rest is the user to eyeball

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
		// For now we only support single keys
		_, err = jws.VerifyWithJWK(jwtToVerify, jwkSet.Keys[0])
		if err != nil {
			return err
		}
		fmt.Println("JWT verified ok")
	}

	if keyFile != "" {
		key, err := getKey()
		if err != nil {
			return err
		}

		// Try all of the valid algs for the type of key
		algs, _, err := getAlgsForKeyType(key)
		ok := false
		for _, alg := range algs {
			_, err := jws.Verify(jwtToVerify, jwa.SignatureAlgorithm(alg), key)
			if err == nil {
				ok = true
				break
			} else {
				fmt.Println(err)
			}
		}
		if ok {
			fmt.Println("JWT verified ok")
		} else {
			return errors.New("Could not verify JWT using supplied key")
		}
	}

	return nil
}
