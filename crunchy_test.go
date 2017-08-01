package crunchy

import "testing"

var (
	invalidPws = []struct {
		pw       string
		expected error
	}{
		{"", ErrEmpty},
		{" ", ErrEmpty},
		{"crnch", ErrTooShort},
		{"aaaaaa", ErrTooFewChars},
		{"abcddd", ErrTooFewChars},
		{"123456", ErrTooSystematic},
		{"654321", ErrTooSystematic},
		{"abcdef", ErrTooSystematic},
		{"fedcba", ErrTooSystematic},
		// {"password", ErrDictionary},
		// {"backdoor", ErrDictionary},
	}
	validPws = []string{"d1924ce3d0510b2b2b4604c99453e2e1"}
)

func TestValidatePassword(t *testing.T) {
	for _, pw := range validPws {
		err := ValidatePassword(pw)
		if err != nil {
			t.Errorf("Expected no error for valid password '%s', got %v", pw, err)
		}
	}

	for _, pw := range invalidPws {
		err := ValidatePassword(pw.pw)
		if err != pw.expected {
			t.Errorf("Expected %v for invalid password '%s', got %v", pw.expected, pw.pw, err)
		}
	}
}
