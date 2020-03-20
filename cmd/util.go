package cmd

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"

	"github.com/dvsekhvalnov/jose2go/base64url"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

type internalJwt struct {
	unsigned *jwt.Token
	signed   []byte
}

type jwtCliKey struct {
	privateKey crypto.PrivateKey
	alg        jwa.SignatureAlgorithm
}

type jwtCliError struct {
	reason string
}

func exit(e error) {
	fmt.Fprintln(os.Stderr, e)
	os.Exit(1)
}

func (j *jwtCliError) Error() string {
	return fmt.Sprintln(j.reason)
}

func (j *internalJwt) writeJwt() error {

	// Check output filename
	var printFile *os.File
	if outputFile != "" {
		printFilePtr, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
		defer printFilePtr.Close()
		if err != nil {
			return &jwtCliError{reason: fmt.Sprintln(err)}
		}
		printFile = printFilePtr
	} else {
		printFile = os.Stdout
	}
	if decode && j.signed != nil {
		decodedJWT := decodeSignedJWT(j.signed)
		fmt.Fprintln(printFile, decodedJWT)
		return nil
	} else if j.signed != nil {
		fmt.Fprintln(printFile, string(j.signed))
		return nil
	} else {
		jsonByte, err := json.Marshal(j.unsigned)
		if err != nil {
			return err
		}
		fmt.Fprintln(printFile, string(jsonByte))
		return nil
	}
	return &jwtCliError{reason: "Error writing JWT"}
}

/*
func getOutputFile() (*os.File, error) {
	// TODO
	return os.Stdout, nil
}*/

func (j *internalJwt) sign(k *jwtCliKey) error {
	if j.signed != nil {
		return &jwtCliError{reason: "Internal error: JWT is alread signed"}
	}
	signed, err := j.unsigned.Sign(k.alg, k.privateKey)
	if err != nil {
		return &jwtCliError{reason: fmt.Sprintln(err)}
	}
	j.signed = signed
	return nil
}

// Gets the key from the filesystem or generates one
func getKey() (*jwtCliKey, error) {
	// TODO cover the user provided key case
	if key != "" {
		return nil, &jwtCliError{reason: "not implemented"}
	}
	generatedKey, err := rsa.GenerateKey(rand.Reader, keyLen)
	if err != nil {
		return nil, err
	}
	return &jwtCliKey{privateKey: generatedKey, alg: jwa.RS256}, nil
}

func decodeSignedJWT(buf []byte) string {
	headB64U, payloadB64U, sig, err := jws.SplitCompact(bytes.NewReader(buf))
	if err != nil {
		panic(fmt.Sprintln(err))
	}

	var jwtParts = [][]byte{headB64U, payloadB64U}
	for i := range jwtParts {
		jwtParts[i], err = base64url.Decode(string(jwtParts[i]))
		if err != nil {
			panic(fmt.Sprintln(err))
		}
	}
	return fmt.Sprintf("%s\n%s\n%s", jwtParts[0], jwtParts[1], sig)

}
