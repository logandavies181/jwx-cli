package cmd

import(
	"fmt"
	"bytes"

	"github.com/lestrrat-go/jwx/jws"
	"github.com/dvsekhvalnov/jose2go/base64url"
)

func decodeSignedJWT (buf []byte) string {
	headB64U, payloadB64U, sig, err := jws.SplitCompact(bytes.NewReader(buf))
	if err != nil {
		panic(fmt.Sprintln(err))
	}

	var jwtParts = [][]byte{headB64U,payloadB64U}
	for i := range(jwtParts) {
		jwtParts[i], err = base64url.Decode(string(jwtParts[i]))
		if err != nil {
			panic(fmt.Sprintln(err))
		}
	}
	return fmt.Sprintf("%s\n%s\n%s",jwtParts[0],jwtParts[1],sig)

}
