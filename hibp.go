package crunchy

import (
	"crypto/sha1"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

var HttpClient = &http.Client{
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 30 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: 10 * time.Second,
	},
}

func foundInHIBP(s string) error {
	h := sha1.New()
	h.Write([]byte(s))
	result := hex.EncodeToString(h.Sum(nil))

	firstFive := result[0:5]
	restOfHash := strings.ToUpper(result[5:])

	url := "https://api.pwnedpasswords.com/range/" + firstFive

	resp, err := HttpClient.Get(url)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if strings.Index(string(body), restOfHash) > -1 {
		return ErrFoundHIBP
	}

	return nil
}
