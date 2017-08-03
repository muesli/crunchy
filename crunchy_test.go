/*
 * crunchy - find common flaws in passwords
 *     Copyright (c) 2017, Christian Muehlhaeuser <muesli@gmail.com>
 *
 *   For license see LICENSE
 */

package crunchy

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"strconv"
	"testing"
)

var (
	invalidPws = []struct {
		pw       string
		expected error
	}{
		{"", ErrEmpty},
		{" ", ErrEmpty},
		{"crunchy", ErrTooShort},
		{"aaaaaaaa", ErrTooFewChars},
		{"aabbccdd", ErrTooFewChars},
		{"12345678", ErrTooSystematic},
		{"87654321", ErrTooSystematic},
		{"abcdefgh", ErrTooSystematic},
		{"hgfedcba", ErrTooSystematic},

		{"password", ErrDictionary},
		{"intoxicate", ErrDictionary},
		{"p@ssw0rd", ErrMangledDictionary},    // dictionary with mangling
		{"!pass@word?", ErrMangledDictionary}, // dictionary with mangling
		{"drowssap", ErrMangledDictionary},    // reversed dictionary
		{"?drow@ssap!", ErrMangledDictionary}, // reversed dictionary with mangling

		{"5f4dcc3b5aa765d61d8327deb882cf99", ErrHashedDictionary},                                                                                                 // md5 dictionary lookup
		{"5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", ErrHashedDictionary},                                                                                         // sha1 dictionary lookup
		{"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", ErrHashedDictionary},                                                                 // sha256 dictionary lookup
		{"b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86", ErrHashedDictionary}, // sha512 dictionary lookup
	}
	validPws = []string{"d1924ce3d0510b2b2b4604c99453e2e1"}
)

func TestValidatePassword(t *testing.T) {
	v := NewValidatorWithOpts(Options{
		MinDist:        -1,
		Hashers:        []hash.Hash{md5.New(), sha1.New(), sha256.New(), sha512.New()},
		DictionaryPath: "/usr/share/dict",
	})

	for _, pw := range validPws {
		err := v.Check(pw)
		if err != nil {
			t.Errorf("Expected no error for valid password '%s', got %v", pw, err)
		}
	}

	for _, pw := range invalidPws {
		err := v.Check(pw.pw)
		if err != pw.expected {
			t.Errorf("Expected %v for invalid password '%s', got %v", pw.expected, pw.pw, err)
		}
	}
}

func BenchmarkValidatePassword(b *testing.B) {
	v := NewValidator()
	s := hashsum(strconv.Itoa(b.N), md5.New())

	for n := 0; n < b.N; n++ {
		v.Check(s)
	}
}
