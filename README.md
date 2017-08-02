crunchy
=======

Finds common flaws in passwords. Like cracklib, but written in Go.

Detects:
 - Empty passwords `ErrEmpty`
 - Too short passwords `ErrTooShort`
 - Systematic passwords, like "abcdef" or "654321" `ErrTooSystematic`
 - Passwords from a dictionary / wordlist `ErrDictionary`

## Installation

Make sure you have a working Go environment. See the [install instructions](http://golang.org/doc/install.html).

To install crunchy, simply run:

    go get github.com/muesli/crunchy

To compile it from source:

    cd $GOPATH/src/github.com/muesli/crunchy
    go get -u -v
    go build && go test -v

## Example
```go
package main

import (
	"github.com/muesli/crunchy"
	"fmt"
)

func main() {
    err := crunchy.ValidatePassword("123456")
    if err != nil {
        fmt.Printf("The password '%s' is considered unsafe: %v\n", "123456", err)
    }

    err = crunchy.ValidatePassword("d1924ce3d0510b2b2b4604c99453e2e1")
    if err == nil {
        // Password is considered acceptable
        ...
    }
}
```

## Development

API docs can be found [here](http://godoc.org/github.com/muesli/crunchy).

[![Build Status](https://secure.travis-ci.org/muesli/crunchy.png)](http://travis-ci.org/muesli/crunchy)
[![Coverage Status](https://coveralls.io/repos/github/muesli/crunchy/badge.svg?branch=master)](https://coveralls.io/github/muesli/crunchy?branch=master)
[![Go ReportCard](http://goreportcard.com/badge/muesli/crunchy)](http://goreportcard.com/report/muesli/crunchy)
