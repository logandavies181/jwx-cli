package cmd

import (
	"fmt"
	"crypto"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/spf13/cobra"
)

// generateCmd represents the generate command
var jwkGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		jwkGenerateMain()
	},
}

func init() {
	jwkCmd.AddCommand(jwkGenerateCmd)

}

func jwkGenerateMain() {
	// TODO: allow reading from private key

	key, err := getKey()
	if err != nil {
		exit(err)
	}
	fmt.Println("got key")
	// TODO tidy up switches
	var jwkKeyInterface jwk.Key
	switch v := key.Key.(type){
	case crypto.PrivateKey:
		jwkKeyInterface, _ = jwk.New(v)
		if err != nil {
			exit(err)
		}
	case crypto.PublicKey:
		jwkKeyInterface, _ = jwk.New(v)
		if err != nil {
			exit(err)
		}
	default: 
		exit(&jwxCliError{reason: fmt.Sprintln("Key type not found ", v)})
	}


//	jwkKeyInterface, err := jwk.New(&key.Key)
	if err != nil {
		exit(err)
	}
	fmt.Println("debug near end")
//	jwkKey := jwkKeyInterface.(*jwk.RSAPrivateKey)
	switch v := jwkKeyInterface.(type) {
	case *jwk.RSAPrivateKey:
		jwkJSON, err := v.MarshalJSON()
		if err != nil {
			exit(err)
		}

		fmt.Println(string(jwkJSON))
	case *jwk.RSAPublicKey:
		jwkJSON, err := v.MarshalJSON()
		if err != nil {
			exit(err)
		}

		fmt.Println(string(jwkJSON))
	default:
		fmt.Println("error")
	}
}
