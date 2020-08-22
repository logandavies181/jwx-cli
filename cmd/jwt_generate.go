package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/spf13/cobra"
)

var (
	octetAlgs = []string{"HS256", "HS383", "HS512"}
	ecAlgs    = []string{"ES256", "ES384", "ES512"}
	rsaAlgs   = []string{"PS256", "PS384", "PS512", "RS256", "RS384", "RS512"}
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
	noSig                        bool
	algorithm                    string
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
	jwtGenerateCmd.Flags().BoolVarP(&symmetric, "symmetric-key", "", false, "Indicates the key is a symmetric key")
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

func signJWT(token jwt.Token) ([]byte, error) {
	// TODO: allow using jwk to sign
	key, err := getKey()
	if err != nil {
		return nil, err
	}

	allowedAlgs, algType, err := checkAlgsForKey(key)
	if err != nil {
		return nil, err
	}

	algOk := false
	for _, alg := range allowedAlgs {
		if alg == algorithm {
			algOk = true
		}
	}
	if !algOk {
		return nil, errors.New(fmt.Sprintf("You must supply a valid alg for your key. Valid algs for %v are %v", algType, strings.Join(allowedAlgs, ", ")))
	}
	// TODO: check the key type and return valid algs
	if algorithm == "" {
		return nil, errors.New("Must supply alg to sign with")
	}

	// TODO!! implement checkAlgsForKey so we can check that the alg is right

	// TODO: finish correlating alg input to real alg
	signedBytes, err := jwt.Sign(token, jwa.RS256, key)
	if err != nil {
		return nil, err
	}
	return signedBytes, nil
}

// This func wraps the token.Set call to print errors to stderr without failing
// TODO: allow silence
func setWrapper(key string, value interface{}, token jwt.Token) {
	err := token.Set(key, value)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func checkAlgsForJWK(key jwk.Key) ([]string, string, error) {
	switch key.KeyType() {
	case jwa.EC:
		return ecAlgs, "ECDSA", nil
	case jwa.OctetSeq:
		return octetAlgs, "Symmetric", nil
	case jwa.RSA:
		return rsaAlgs, "RSA", nil
	default:
		return nil, "", errors.New("Invalid key type")
	}
}

// TODO!!
func checkAlgsForKey(key cryptoKey) ([]string, string, error) {
	switch key.(type) {
	case rsa.PublicKey:
		return rsaAlgs, "RSA", nil
	case rsa.PrivateKey:
		return rsaAlgs, "RSA", nil
	case ecdsa.PrivateKey:
		return ecAlgs, "ECDSA", nil
	case ecdsa.PublicKey:
		return ecAlgs, "ECDSA", nil
	default:
		if symmetric {
			return octetAlgs, "Symmetric", nil
		} else {
			return nil, "", errors.New("Could not determine algs for key")
		}
	}
}
