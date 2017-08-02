package crunchy

import (
	"errors"
	"io/ioutil"
	"path/filepath"
	"strings"
	"sync"

	"github.com/xrash/smetrics"
)

var (
	// MinDiff is the minimum amount of unique characters required for a valid password
	MinDiff = 5
	// MinLength is the minimum length required for a valid password
	MinLength = 6

	// ErrEmpty gets returned when the password is empty or all whitespace
	ErrEmpty = errors.New("Password is empty or all whitespace")
	// ErrTooShort gets returned when the password is not long enough
	ErrTooShort = errors.New("Password is too short")
	// ErrTooFewChars gets returned when the password does not contain enough unique characters
	ErrTooFewChars = errors.New("Password does not contain enough different/unique characters")
	// ErrTooSystematic gets returned when the password is too systematic (e.g. 123456, abcdef)
	ErrTooSystematic = errors.New("Password is too systematic")
	// ErrDictionary gets returned when the password is found in a dictionary
	ErrDictionary = errors.New("Password is too common / from a dictionary")
	// ErrMangledDictionary gets returned when the password is mangled, but found in a dictionary
	ErrMangledDictionary = errors.New("Password is mangled, but too common / from a dictionary")
	// ErrHashedDictionary gets returned when the password is hashed, but found in a dictionary
	ErrHashedDictionary = errors.New("Password is hashed, but too common / from a dictionary")

	once  sync.Once
	words = make(map[string]struct{})
)

func countUniqueChars(s string) int {
	m := make(map[rune]struct{})

	for _, c := range s {
		if _, ok := m[c]; !ok {
			m[c] = struct{}{}
		}
	}

	return len(m)
}

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

func reverse(s string) string {
	rs := []rune(s)
	for i, j := 0, len(rs)-1; i < j; i, j = i+1, j-1 {
		rs[i], rs[j] = rs[j], rs[i]
	}
	return string(rs)
}

func normalize(s string) string {
	return strings.TrimSpace(strings.ToLower(s))
}

func indexDictionaries() {
	dicts, err := filepath.Glob("/usr/share/dict/*")
	if err != nil {
		return
	}

	for _, dict := range dicts {
		buf, err := ioutil.ReadFile(dict)
		if err != nil {
			continue
		}

		for _, word := range strings.Split(string(buf), "\n") {
			words[normalize(word)] = struct{}{}
		}
	}
}

func foundInDictionaries(s string) (string, error) {
	once.Do(indexDictionaries)

	pw := normalize(s)     // normalized password
	revpw := reverse(pw)   // reversed password
	mindist := len(pw) / 2 // minimum distance
	if mindist > 3 {
		mindist = 3
	}

	// let's check perfect matches first
	if _, ok := words[pw]; ok {
		if s == pw {
			return pw, ErrDictionary
		}
		return pw, ErrMangledDictionary
	}
	if _, ok := words[revpw]; ok {
		return revpw, ErrMangledDictionary
	}

	for word := range words {
		if dist := smetrics.WagnerFischer(word, pw, 1, 1, 1); dist <= mindist {
			// fmt.Printf("%s is too similar to %s\n", pw, word)
			return word, ErrMangledDictionary
		}
		if dist := smetrics.WagnerFischer(word, revpw, 1, 1, 1); dist <= mindist {
			// fmt.Printf("Reversed %s (%s) is too similar to %s: %d\n", pw, revpw, word, dist)
			return word, ErrMangledDictionary
		}
	}

	return "", nil
}

// ValidatePassword checks password for common flaws
// It returns nil if the password is considered acceptable.
func ValidatePassword(password string) error {
	if strings.TrimSpace(password) == "" {
		return ErrEmpty
	}
	if len(password) < MinLength {
		return ErrTooShort
	}
	if countUniqueChars(password) < MinDiff {
		return ErrTooFewChars
	}

	// Inspired by cracklib
	maxrepeat := 3.0 + (0.09 * float64(len(password)))
	if countSystematicChars(password) > int(maxrepeat) {
		return ErrTooSystematic
	}

	if _, err := foundInDictionaries(password); err != nil {
		return err
	}

	return nil
}
