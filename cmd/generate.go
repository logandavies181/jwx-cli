package cmd

import (
	"fmt"
	"encoding/json"
	"bytes"
	"crypto/rand"
	"crypto/rsa"

	"github.com/spf13/cobra"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/lestrrat-go/jwx/jws"
)

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a jwt",
	Run: func(cmd *cobra.Command, args []string) {
		jwtGenerateMain()
	},
}
var attr map[string]string

func init() {
	jwtCmd.AddCommand(generateCmd)

	generateCmd.Flags().StringToStringVarP(&attr,"attr", "a", make(map[string]string) ,"List of key-value pairs to add to payload e.g. 'sub=foo,iss=bar")
}

func jwtGenerateMain() {
	tok := jwt.New()

	for k,v := range(attr) {
		tok.Set(k,v)
	}

	b1,b2,b3,err := jws.SplitCompact(bytes.NewReader(tok))
	buf, err := json.MarshalIndent(tok, "", "  ")
	if err != nil {
		fmt.Printf("failed to generate JSON: %s\n", err)
		return
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to generate private key: %s\n", err)
		return
	}
	var payload []byte
	payload, err = tok.Sign(jwa.RS256, privKey)
	if err != nil {
		fmt.Printf("failed to generate signed payload: %s\n", err)
		return
	}
	fmt.Printf("%s",payload)
	fmt.Printf("%s\n", buf)
	//b1,b2,b3,err := jws.SplitCompact(bytes.NewReader(payload))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(b1),string(b2),string(b3))
}
