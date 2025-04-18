// Package secparse provides functions to parse secrets from various formats.
// It can parse secrets from legacy MIME format, YAML format, and AKV format.
package secparse

import (
	"errors"

	"github.com/gopasspw/gopass/internal/out"
	"github.com/gopasspw/gopass/pkg/debug"
	"github.com/gopasspw/gopass/pkg/gopass"
	"github.com/gopasspw/gopass/pkg/gopass/secrets"
)

// Parse tries to parse a secret. It will start with the most specific
// secrets type.
//
//nolint:ireturn
func Parse(in []byte) (gopass.Secret, error) {
	var s gopass.Secret

	var err error

	s, err = parseLegacyMIME(in)
	if err == nil {
		debug.Log("parsed as MIME: %+v", s)

		return s, nil
	}

	debug.Log("failed to parse as MIME: %s", out.Secret(err.Error()))

	var permError *secrets.PermanentError
	if errors.As(err, &permError) {
		return secrets.ParseAKV(in), err
	}

	s, err = secrets.ParseYAML(in)
	if err == nil {
		debug.Log("parsed as YAML: %+v", s)

		return s, nil
	}

	debug.Log("failed to parse as YAML: %s\n%s", err, out.Secret(string(in)))

	s = secrets.ParseAKV(in)
	debug.Log("parsed as AVK: %+v", s)

	return s, nil
}

// MustParse parses a secret or panics. Should only be used for tests.
func MustParse(in string) gopass.Secret {
	sec, err := Parse([]byte(in))
	if err != nil {
		panic(err)
	}

	return sec
}
