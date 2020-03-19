package cmd

import (
	"fmt"
	"os"
	//"io/ioutil"
	//"encoding/json"
	//"bytes"
	"crypto/rand"
	"crypto/rsa"

	"github.com/spf13/cobra"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	//"github.com/lestrrat-go/jwx/jws"
)

var (
	generateCmd = &cobra.Command{
		Use:   "generate",
		Short: "Generate a jwt",
		Run: func(cmd *cobra.Command, args []string) {
			jwtGenerateMain()
		},
	}
	
	attr map[string]string
	sign bool
)

func init() {
	jwtCmd.AddCommand(generateCmd)

	generateCmd.Flags().StringToStringVarP(&attr, "attr", "a", make(map[string]string), "List of key-value pairs to add to payload e.g. 'sub=foo,iss=bar")
	generateCmd.Flags().BoolVarP(&sign, "sign", "s", true, "Sign the payload or not")
}

func jwtGenerateMain() {
	tok := jwt.New()

	for k, v := range attr {
		tok.Set(k, v)
	}

	// Add named other attributes here

	if sign {
		signGeneratedJWT(tok)
	}
}

func signGeneratedJWT(tok *jwt.Token) {
	var payload []byte
	if key == "" {
		// We assume RSA here. Users can generate their own key if they want a different one
		privKey, err := rsa.GenerateKey(rand.Reader, keyLen)
		if err != nil {
			panic(fmt.Sprintf("failed to generate private key: %s\n", err))
		}
		payload, err = tok.Sign(jwa.RS256, privKey)
		if err != nil {
			panic(fmt.Sprintf("failed to generate signed payload: %s\n", err))
		}
	}
	// Logic for user provided key here

	// Check output filename
	var printFile *os.File
	if outputFile != "" {
		printFilePtr, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			panic(err)
		}
		printFile = printFilePtr
	} else {
		printFile = os.Stdout
	}

	fmt.Fprintln(printFile, string(payload))
}
