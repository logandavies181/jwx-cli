package cmd

import (
	"bytes"
//	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/dvsekhvalnov/jose2go/base64url"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

type internalJWT struct {
	unsigned *jwt.Token
	signed   []byte
}

type jwxCliKey struct {
	Key cryptoKey
	alg        jwa.SignatureAlgorithm
}

// Should hopefully be crypto.PrivateKey or crypto.PublicKey
type cryptoKey interface{}

type jwxCliError struct {
	reason string
}

func exit(e error) {
	fmt.Fprintln(os.Stderr, e)
	os.Exit(1)
}

func (j *jwxCliError) Error() string {
	return fmt.Sprintln(j.reason)
}

func (j *internalJWT) writeJWT() error {

	// Check output filename
	var printFile *os.File
	if outputFile != "" {
		printFilePtr, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
		defer printFilePtr.Close()
		if err != nil {
			return &jwxCliError{reason: fmt.Sprintln(err)}
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
	return &jwxCliError{reason: "Error writing JWT"}
}

func (j *internalJWT) sign(k *jwxCliKey) error {
	if j.signed != nil {
		return &jwxCliError{reason: "Internal error: JWT is alread signed"}
	}
	signed, err := j.unsigned.Sign(k.alg, k.Key)
	if err != nil {
		return &jwxCliError{reason: fmt.Sprintln(err)}
	}
	j.signed = signed
	return nil
}

// Gets the key from the filesystem or generates one
func getKey() (*jwxCliKey, error) {
	// TODO allow non-pem format
	if keyFile != "" {
		keyFileR, err := os.Open(keyFile)
		defer keyFileR.Close()
		if err != nil {
			return nil, err
		}
		dat, err := ioutil.ReadAll(keyFileR)
		if err != nil {
			return nil, err
		}

		keyBlock, _ := pem.Decode(dat)
		if keyBlock == nil { 
			return nil, &jwxCliError{reason: "No valid private key found in PEM"}
		}
		fmt.Println(keyBlock.Type)
		var pemKey cryptoKey
		if keyBlock.Type == "RSA PRIVATE KEY" {
			privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			if err != nil {
				return nil, err
			}
			pemKey = privateKey
		} else if keyBlock.Type == "PUBLIC KEY" {
			fmt.Println("public")
			publicKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
			if err != nil {
				fmt.Println("failed pub")
				return nil, err
			}
			pemKey = publicKey
		} else {
			return nil, &jwxCliError{reason: "Failed to parse key file"}
		}

		// TODO don't assume RSA
		return &jwxCliKey{Key: pemKey, alg: jwa.RS512}, nil

	}
	generatedKey, err := rsa.GenerateKey(rand.Reader, keyLen)
	if err != nil {
		return nil, err
	}
	return &jwxCliKey{Key: generatedKey, alg: jwa.RS512}, nil
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

func readFile(filename string) ([]byte, error) {
	filenameRead, err := os.Open(filename)
	defer filenameRead.Close()
	if err != nil {
		return nil, err
	}

	dat, err := ioutil.ReadAll(filenameRead)
	if err != nil {
		return nil, err
	}
	return dat, nil
}

// might not be useful as jwk.Token doesn't include signature
/*
func readJWTFromFile(filename string) (*internalJWT, error) {
	dat, err := readFile(filename)
	if err != nil {
		return nil, err
	}
	parsedJWT, err := jwt.ParseBytes(dat)
	if err != nil {
		return nil, err
	}
	return &internalJWT{}
}
*/
