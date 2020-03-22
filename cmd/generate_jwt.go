package cmd

import (
	//"fmt"
	//"os"
	//"io/ioutil"
	//"encoding/json"
	//"bytes"
	//"crypto/rand"
	//"crypto/rsa"

	//"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/spf13/cobra"
	//"github.com/lestrrat-go/jwx/jws"
)

var (
	jwtGenerateCmd = &cobra.Command{
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
	jwtCmd.AddCommand(jwtGenerateCmd)

	jwtGenerateCmd.Flags().StringToStringVarP(&attr, "attr", "a", make(map[string]string), "List of key-value pairs to add to payload e.g. 'sub=foo,iss=bar'")
	jwtGenerateCmd.Flags().BoolVarP(&sign, "sign", "s", true, "Sign the payload or not")
}

func jwtGenerateMain() {
	tok := internalJWT{unsigned: jwt.New()}

	for k, v := range attr {
		tok.unsigned.Set(k, v)
	}

	// Add named other attributes here

	if sign {
		signingKey, err := getKey()
		if err != nil {
			exit(err)
		}

		err = tok.sign(signingKey)
		if err != nil {
			exit(err)
		}
	}

	err := tok.writeJWT()
	if err != nil {
		exit(err)
	}
}