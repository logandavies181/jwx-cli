package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/spf13/cobra"
)

// So jwk.Key and jwt.Token can both use setWrapper
type getterSetter interface {
	Get(string) (interface{}, bool)
	Set(string, interface{}) error
}

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

	m, err = timeFieldsToUnix(m)
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
func setWrapper(key string, value interface{}, target getterSetter) {
	err := target.Set(key, value)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

// Expect case string when reading JSON, case time.Time while generating a JWT, 
// and case nil when the field doesn't exist
func timeFieldsToUnix(m map[string]interface{}) (map[string]interface{}, error) {

	for _, field := range []string{"exp", "iat", "nbf"} {
		switch v := m[field].(type) {
		case string:
			unixTime, err := time.Parse("2006-01-02T15:04:05Z", v)
			if err != nil {
				return nil, errors.New(fmt.Sprintf("Unable to parse %v, value %v",field, v))
			} 
			m[field] = unixTime
		case float64:
			// do nothing. this is the type that it probably should have been 
			// in the first place
			// TODO: test lol
		case nil:
			// no nothing. No value found for key
		case time.Time:
			m[field] = v.Unix()
		default:
			return nil, errors.New(fmt.Sprintf("Unable to parse value in token:\nvalue: %v\ntype: %T", v, v))
		}
	}

	return m, nil
}
