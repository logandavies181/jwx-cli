package util

import (
	"fmt"
	"encoding/base64"
)

func Print(bool b64) {
	if b64 {
		printB64
	}
}
