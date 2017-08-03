package crunchy

import "testing"

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
		{"p@ssw0rd", ErrMangledDictionary},    // dictionary with mangling
		{"!pass@word?", ErrMangledDictionary}, // dictionary with mangling
		{"drowssap", ErrMangledDictionary},    // reversed dictionary
		{"?drow@ssap!", ErrMangledDictionary}, // reversed dictionary with mangling
		{"intoxicate", ErrDictionary},
	}
	validPws = []string{"d1924ce3d0510b2b2b4604c99453e2e1"}
)

func TestValidatePassword(t *testing.T) {
	v := NewValidator()
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
