package cmd

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
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
	jwtSignCmd = &cobra.Command{
		Use:     "sign",
		Aliases: []string{"s"},
		Short:   "Sign a JWT with the specified key or JWKS and with optional headers",
		RunE:    jwtSign,
	}

	algorithm string
	noSig     bool // TODO:
	symmetric bool
)

func init() {
	jwtCmd.AddCommand(jwtSignCmd)

	jwtSignCmd.Flags().StringVarP(&algorithm, "alg", "", "", "JWA algorithm to sign with")
	jwtSignCmd.Flags().StringVarP(&jwtFile, "jwt", "t", "", "JWT file to read from")
	jwtSignCmd.Flags().BoolVarP(&symmetric, "symmetric", "", false, "Indicates the key is a symmetric key")

	jwtSignCmd.MarkFlagRequired("jwt")
	jwtSignCmd.MarkFlagRequired("key")
}

func jwtSign(_ *cobra.Command, _ []string) error {
	jwtDat, err := ioutil.ReadFile(jwtFile)
	if err != nil {
		return err
	}

	// Possible bug with jwt.Parse on an unsigned json. Unmarshalling into
	// empty token copied from jwt.parse implementation..
	// FIXME: unmarshal won't work for the timedate fields as they need to be
	// changed into epoch representation to work with jwt.Token
	var tokenFromMap map[string]interface{}
	err = json.Unmarshal(jwtDat, &tokenFromMap)
	if err != nil {
		return err
	}

	tokenFromMap, err = timeFieldsToUnix(tokenFromMap) 
	if err != nil {
		return err
	}

	token := jwt.New()
	for k, v := range tokenFromMap {
		err := token.Set(k, v)
		if err != nil {
			return err
		}
	}

	signedBytes, err := signJWT(token)
	if err != nil {
		return err
	}
	fmt.Println(string(signedBytes))

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
	algorithmUpper := strings.ToUpper(algorithm)
	for _, alg := range allowedAlgs {
		if alg == algorithmUpper {
			algOk = true
		}
	}
	if !algOk {
		return nil, errors.New(fmt.Sprintf("You must supply a valid alg for your key. Valid algs for %v are %v", algType, strings.Join(allowedAlgs, ", ")))
	}

	// TODO: finish correlating alg input to real alg
	signedBytes, err := jwt.Sign(token, jwa.SignatureAlgorithm(algorithmUpper), key)
	if err != nil {
		return nil, err
	}
	return signedBytes, nil
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

func checkAlgsForKey(key cryptoKey) ([]string, string, error) {
	switch key.(type) {
	case *rsa.PrivateKey:
		return rsaAlgs, "RSA", nil
	case *ecdsa.PrivateKey:
		return ecAlgs, "ECDSA", nil
	default:
		if symmetric {
			return octetAlgs, "Symmetric", nil
		} else {
			return nil, "", errors.New(fmt.Sprintf("Could not determine algs for key type: %T", key))
		}
	}
}

