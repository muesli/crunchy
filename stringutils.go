/*
 * crunchy - find common flaws in passwords
 *     Copyright (c) 2017, Christian Muehlhaeuser <muesli@gmail.com>
 *
 *   For license see LICENSE
 */

package crunchy

import (
	"crypto/sha1"
	"encoding/hex"
	"hash"
	"io/ioutil"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

// countUniqueChars returns the amount of unique runes in a string
func countUniqueChars(s string) int {
	m := make(map[rune]struct{})

	for _, c := range s {
		c = unicode.ToLower(c)
		if _, ok := m[c]; !ok {
			m[c] = struct{}{}
		}
	}

	return len(m)
}

// countSystematicChars returns how many runes in a string are part of a sequence ('abcdef', '654321')
func countSystematicChars(s string) int {
	var x int
	rs := []rune(s)

	for i, c := range rs {
		if i == 0 {
			continue
		}
		if c == rs[i-1]+1 || c == rs[i-1]-1 {
			x++
		}
	}

	return x
}

// reverse returns the reversed form of a string
func reverse(s string) string {
	var rs []rune
	for len(s) > 0 {
		r, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]

		rs = append(rs, r)
	}

	return string(rs)
}

// normalize returns the trimmed and lowercase version of a string
func normalize(s string) string {
	return strings.TrimSpace(strings.ToLower(s))
}

// hashsum returns the hashed sum of a string
func hashsum(s string, hasher hash.Hash) string {
	hasher.Reset()
	hasher.Write([]byte(s))
	return hex.EncodeToString(hasher.Sum(nil))
}

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
