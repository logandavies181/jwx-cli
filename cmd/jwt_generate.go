package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/spf13/cobra"
)

var (
	jwtGenerateCmd = &cobra.Command{
		Use:     "generate",
		Aliases: []string{"gen", "g"},
		Short:   "Generate an unsigned jwt with the desired attributes",
		RunE:    jwtGenerate,
	}

	attr                         map[string]string
	aud                          []string
	exp, iat, iss, jti, nbf, sub string
	sign                         bool
)

func init() {
	jwtCmd.AddCommand(jwtGenerateCmd)

	jwtGenerateCmd.Flags().StringToStringVarP(&attr, "attr", "a", make(map[string]string), "List of key-value pairs to add to payload e.g. 'sub=foo,iss=bar'")

	jwtGenerateCmd.Flags().StringSliceVarP(&aud, "aud", "", []string{}, "Audience")
	jwtGenerateCmd.Flags().StringVarP(&exp, "exp", "", "", "Expiration")
	jwtGenerateCmd.Flags().StringVarP(&iat, "iat", "", "", "IssuedAt")
	jwtGenerateCmd.Flags().StringVarP(&iss, "iss", "", "", "Issuer")
	jwtGenerateCmd.Flags().StringVarP(&jti, "jti", "", "", "JWT ID")
	jwtGenerateCmd.Flags().StringVarP(&nbf, "nbf", "", "", "NotBefore")
	jwtGenerateCmd.Flags().StringVarP(&sub, "sub", "", "", "Subject")

	jwtGenerateCmd.Flags().StringVarP(&algorithm, "alg", "", "", "JWA algorithm to sign with")
	jwtGenerateCmd.Flags().BoolVarP(&symmetric, "symmetric", "", false, "Indicates the key is a symmetric key")
	jwtGenerateCmd.Flags().BoolVarP(&sign, "sign", "s", false, "Whether or not to sign the generated JWT")
}

func jwtGenerate(_ *cobra.Command, _ []string) error {
	token, err := generateJWT()
	if err != nil {
		return err
	}

	if !sign {
		err := printUnsignedJWT(token)
		if err != nil {
			return err
		}
	} else {
		signedBytes, err := signJWT(token)
		if err != nil {
			return err
		}
		fmt.Println(string(signedBytes))
	}
	return nil
}

func generateJWT() (jwt.Token, error) {
	token := jwt.New()
	for k, v := range attr {
		setWrapper(k, v, token)
	}

	// prefer standard headers over arbitrary key/value pairs
	if len(aud) != 0 {
		setWrapper("aud", aud, token)
	}
	if exp != "" {
		setWrapper("exp", exp, token)
	}
	if iat != "" {
		setWrapper("iat", iat, token)
	}
	if iss != "" {
		setWrapper("iss", iss, token)
	}
	if jti != "" {
		setWrapper("jti", jti, token)
	}
	if nbf != "" {
		setWrapper("nbf", nbf, token)
	}
	if sub != "" {
		setWrapper("sub", sub, token)
	}

	return token, nil
}

func printUnsignedJWT(token jwt.Token) error {
	m, err := token.AsMap(context.TODO())
	if err != nil {
		return err
	}

	jwtJSON, err := json.Marshal(m)
	if err != nil {
		return err
	}

	fmt.Println(string(jwtJSON))

	return nil
}

// This func wraps the token.Set call to print errors to stderr without failing
// TODO: allow silence
func setWrapper(key string, value interface{}, token jwt.Token) {
	err := token.Set(key, value)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
