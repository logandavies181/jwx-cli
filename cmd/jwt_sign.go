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
	rsaAlgs   = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}
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
	// Prefer JWK over raw key
	if jwkFile != "" {
		jwKey, err := getJWK()
		if err != nil {
			return nil, err
		}
		alg, err := getAlgorithm(jwKey)
		if err != nil {
			return nil, err
		}
		signedBytes, err := jwt.Sign(token, jwa.SignatureAlgorithm(alg), jwKey)
		if err != nil {
			return nil, err
		}

		return signedBytes, nil
	}

	if keyFile != "" {
		key, err := getKey()
		if err != nil {
			return nil, err
		}
		alg, err := getAlgorithm(key)
		if err != nil {
			return nil, err
		}
		signedBytes, err := jwt.Sign(token, jwa.SignatureAlgorithm(alg), key)
		if err != nil {
			return nil, err
		}
		return signedBytes, nil
	}

	return nil, errors.New("You must supply --key or --jwk")
}

func getAlgsForJWKKeyType(key jwk.Key) ([]string, string, error) {
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

func getAlgsForKeyType(key cryptoKey) ([]string, string, error) {
	switch key.(type) {
	case *rsa.PublicKey:
		return rsaAlgs, "RSA", nil
	case *rsa.PrivateKey:
		return rsaAlgs, "RSA", nil
	case *ecdsa.PrivateKey:
		return ecAlgs, "ECDSA", nil
	case *ecdsa.PublicKey:
		return ecAlgs, "ECDSA", nil
	default:
		if symmetric {
			return octetAlgs, "Symmetric", nil
		} else {
			return nil, "", errors.New(fmt.Sprintf("Could not determine algs for key type: %T", key))
		}
	}
}

// Only return first key if more than one found.
// At this time only support single JWK, not JWKS. Users can use jq to do JWKS stuff
func getJWK() (jwk.Key, error) {
	jwkDat, err := ioutil.ReadFile(jwkFile)
	if err != nil {
		return nil, err
	}
	jwKeys, err := jwk.ParseBytes(jwkDat)
	if err != nil {
		return nil, err
	}
	if len(jwKeys.Keys) == 0 {
		return nil, errors.New(fmt.Sprintf("0 keys parsed from %v", jwkFile))
	}

	return jwKeys.Keys[0], nil
}

// Called when --alg flag not supplied. Check if alg header set on jwk. Return
// something sensible if not
func getDefaultAlg(key jwk.Key) (string, error) {
	if keyAlg := key.Algorithm(); keyAlg != "" {
		return keyAlg, nil
	}

	switch keyType := key.KeyType(); keyType {
	case jwa.EC:
		return ecAlgs[0], nil
	case jwa.RSA:
		return rsaAlgs[0], nil
	case jwa.OctetSeq:
		return octetAlgs[0], nil
	default:
		return "", errors.New("Could not find a valid alg. Invalid key type")
	}
}

// Get the algorithm if not supplied and check for validity
func getAlgorithm(key interface{}) (string, error) {
	switch v := key.(type) {
	case jwk.Key:
		allowedAlgs, algType, err := getAlgsForJWKKeyType(v)
		if err != nil {
			return "", err
		}
		algorithm = strings.ToUpper(algorithm)
		if algorithm != "" {
			algOk := false
			for _, alg := range allowedAlgs {
				if alg == algorithm {
					algOk = true
				}
			}
			if !algOk {
				return "", errors.New(fmt.Sprintf("You must supply a valid alg for your key. Valid algs for %v are %v", algType, strings.Join(allowedAlgs, ", ")))
			}
		} else {
			return getDefaultAlg(v)
		}
	case cryptoKey:
		allowedAlgs, algType, err := getAlgsForKeyType(key)
		if err != nil {
			return "", err
		}

		algorithm = strings.ToUpper(algorithm)
		if algorithm != "" {
			algOk := false
			for _, alg := range allowedAlgs {
				if alg == algorithm {
					algOk = true
				}
			}
			if !algOk {
				return "", errors.New(fmt.Sprintf("You must supply a valid alg for your key. Valid algs for %v are %v", algType, strings.Join(allowedAlgs, ", ")))
			}
		} else {
			parsedKey, err := jwk.New(key)
			if err != nil {
				return "", err
			}
			return getDefaultAlg(parsedKey)
		}
	default:
		return "", errors.New(fmt.Sprintf("Could not determine algorithm for type %T", v))
	}
	return "", errors.New("Unknown error")
}
