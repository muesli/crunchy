package crunchy

import (
	"crypto/sha1"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"strings"
)

func foundInHIBP(s string) error {
	h := sha1.New()
	h.Write([]byte(s))
	result := hex.EncodeToString(h.Sum(nil))

	firstFive := result[0:5]
	restOfHash := strings.ToUpper(result[5:])

	url := "https://api.pwnedpasswords.com/range/" + firstFive

	resp, err := http.Get(url)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if strings.Index(string(body), restOfHash) > -1 {
		return ErrFoundHIBP
	}

	return nil
}
