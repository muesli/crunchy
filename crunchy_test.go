/*
 * crunchy - find common flaws in passwords
 *     Copyright (c) 2017-2018, Christian Muehlhaeuser <muesli@gmail.com>
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
	pws = []struct {
		pw       string
		expected error
		rating   uint
	}{
		// valid passwords
		{"d1924ce3d0510b2b2b4604c99453e2e1", nil, 100},
		{"aCgIknPv", nil, 40},
		{"1347902586", nil, 37},
		{"aEc!1Edek?", nil, 71},
		{"aEc!1Edek?f", nil, 77},
		{"aEc!1Edek?f_", nil, 91},
		{"aEc!1Edek?f_0", nil, 100},

		// invalid passwords
		{"", ErrEmpty, 0},
		{" ", ErrEmpty, 0},
		{"crunchy", ErrTooShort, 0},
		{"aaaaaaaa", ErrTooFewChars, 0},
		{"aabbccdd", ErrTooFewChars, 0},
		{"aAbBcCdD", ErrTooFewChars, 0},
		{"12345678", ErrTooSystematic, 0},
		{"87654321", ErrTooSystematic, 0},
		{"abcdefgh", ErrTooSystematic, 0},
		{"hgfedcba", ErrTooSystematic, 0},

		// haveibeenpwnd
		{"Qwertyuiop", ErrFoundHIBP, 0},

		{"password", ErrDictionary, 0},
		{"intoxicate", ErrDictionary, 0},
		{"p@ssw0rd", ErrMangledDictionary, 0},    // dictionary with mangling
		{"!pass@word?", ErrMangledDictionary, 0}, // dictionary with mangling
		{"drowssap", ErrMangledDictionary, 0},    // reversed dictionary
		{"?drow@ssap!", ErrMangledDictionary, 0}, // reversed dictionary with mangling

		// md5 dictionary lookup
		{"5f4dcc3b5aa765d61d8327deb882cf99", ErrHashedDictionary, 0},
		// sha1 dictionary lookup
		{"5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", ErrHashedDictionary, 0},
		// sha256 dictionary lookup
		{"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", ErrHashedDictionary, 0},
		// sha512 dictionary lookup
		{"b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86", ErrHashedDictionary, 0},
	}
)

func TestValidator(t *testing.T) {
	v := NewValidator()

	pw := "crunchy"
	err := v.Check(pw)
	if err == nil {
		t.Errorf("Expected %v for password '%s', got nil", ErrTooShort, pw)
	}
}

func TestRatePassword(t *testing.T) {
	v := NewValidatorWithOpts(Options{
		MinDist:        -1,
		Hashers:        []hash.Hash{md5.New(), sha1.New(), sha256.New(), sha512.New()},
		DictionaryPath: "/usr/share/dict",
	})

	for _, pw := range pws {
		if pw.expected == ErrFoundHIBP {
			continue
		}
		r, err := v.Rate(pw.pw)
		if dicterr, ok := err.(*DictionaryError); ok {
			err = dicterr.Err
		} else if hasherr, ok := err.(*HashedDictionaryError); ok {
			err = hasherr.Err
		}

		if r != pw.rating {
			t.Errorf("Expected rating %d for password '%s', got %d", pw.rating, pw.pw, r)
		}
		if err != pw.expected {
			t.Errorf("Expected %v for password '%s', got %v", pw.expected, pw.pw, err)
		}
	}
}

func TestCheckHIBP(t *testing.T) {
	v := NewValidatorWithOpts(Options{
		CheckHIBP: true,
	})

	for _, pw := range pws {
		if pw.expected != ErrFoundHIBP {
			continue
		}

		er := v.Check(pw.pw)
		if er != pw.expected {
			t.Errorf("Expected %v for password '%s', got %v", pw.expected, pw.pw, er)
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
