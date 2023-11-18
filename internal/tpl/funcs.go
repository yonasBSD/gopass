package tpl

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/gopasspw/gopass/internal/hashsum"
	"github.com/gopasspw/gopass/internal/pwschemes/argon2i"
	"github.com/gopasspw/gopass/internal/pwschemes/argon2id"
	"github.com/gopasspw/gopass/pkg/debug"
)

// These constants defined the template function names used.
const (
	FuncBlake3        = "blake3"
	FuncGet           = "get"
	FuncGetPassword   = "getpw"
	FuncGetValue      = "getval"
	FuncGetValues     = "getvals"
	FuncArgon2i       = "argon2i"
	FuncArgon2id      = "argon2id"
	FuncBcrypt        = "bcrypt"
	FuncJoin          = "join"
	FuncRoundDuration = "roundDuration"
	FuncDate          = "date"
	FuncTruncate      = "truncate"
)

func blake3sum() func(...string) (string, error) {
	return func(s ...string) (string, error) {
		return hashsum.Blake3Hex(s[0]), nil
	}
}

// saltLen tries to parse the given string into a numeric salt length.
func saltLen(s []string) uint8 {
	if len(s) < 2 {
		debug.Log("no salt length given, using default %d", 32)

		return 32
	}

	i, err := strconv.ParseUint(s[0], 10, 8)
	if err != nil {
		debug.Log("failed to parse saltLen %+v: %q. using default: %d", s, err, 32)

		return 32
	}

	sl := uint8(i)

	debug.Log("using saltLen %d", sl)

	return sl
}

func argon2iFunc() func(...string) (string, error) {
	// parameters: s[0] = salt, s[-1] = password
	return func(s ...string) (string, error) {
		if len(s) < 1 {
			return "", fmt.Errorf("usage: %s <salt> <password>", FuncArgon2i)
		}

		return argon2i.Generate(s[len(s)-1], uint32(saltLen(s))) //nolint:wrapcheck
	}
}

func argon2idFunc() func(...string) (string, error) {
	// parameters: s[0] = salt, s[-1] = password
	return func(s ...string) (string, error) {
		if len(s) < 1 {
			return "", fmt.Errorf("usage: %s <salt> <password> or <password>", FuncArgon2id)
		}

		return argon2id.Generate(s[len(s)-1], uint32(saltLen(s))) //nolint:wrapcheck
	}
}

func get(ctx context.Context, kv kvstore) func(...string) (string, error) {
	return func(s ...string) (string, error) {
		if len(s) < 1 {
			return "", nil
		}

		if kv == nil {
			return "", fmt.Errorf("KV is nil")
		}

		sec, err := kv.Get(ctx, s[0])
		if err != nil {
			return err.Error(), nil
		}

		return string(sec.Bytes()), nil
	}
}

func getPassword(ctx context.Context, kv kvstore) func(...string) (string, error) {
	return func(s ...string) (string, error) {
		if len(s) < 1 {
			return "", nil
		}

		if kv == nil {
			return "", fmt.Errorf("KV is nil")
		}

		sec, err := kv.Get(ctx, s[0])
		if err != nil {
			return err.Error(), nil
		}

		return sec.Password(), nil
	}
}

func getValue(ctx context.Context, kv kvstore) func(...string) (string, error) {
	return func(s ...string) (string, error) {
		if len(s) < 2 {
			return "", nil
		}

		if kv == nil {
			return "", fmt.Errorf("KV is nil")
		}

		sec, err := kv.Get(ctx, s[0])
		if err != nil {
			return err.Error(), nil
		}

		sv, found := sec.Get(s[1])
		if !found {
			return "", fmt.Errorf("key %q not found", s[1])
		}

		return sv, nil
	}
}

func getValues(ctx context.Context, kv kvstore) func(...string) ([]string, error) {
	return func(s ...string) ([]string, error) {
		if len(s) < 2 {
			return nil, nil
		}

		if kv == nil {
			return nil, fmt.Errorf("KV is nil")
		}

		sec, err := kv.Get(ctx, s[0])
		if err != nil {
			return nil, fmt.Errorf("failed to get %q: %w", s[0], err)
		}

		values, found := sec.Values(s[1])
		if !found {
			return nil, fmt.Errorf("key %q not found", s[1])
		}

		return values, nil
	}
}

func roundDuration(duration any) string {
	var d time.Duration
	switch duration := duration.(type) {
	case string:
		d, _ = time.ParseDuration(duration)
	case int64:
		d = time.Duration(duration)
	case time.Time:
		d = time.Since(duration)
	case time.Duration:
		d = duration
	default:
		d = 0
	}

	u := uint64(d)
	year := uint64(time.Hour) * 24 * 365
	month := uint64(time.Hour) * 24 * 30
	day := uint64(time.Hour) * 24
	hour := uint64(time.Hour)
	minute := uint64(time.Minute)
	second := uint64(time.Second)

	switch {
	case u > year:
		return strconv.FormatUint(u/year, 10) + "y"
	case u > month:
		return strconv.FormatUint(u/month, 10) + "mo"
	case u > day:
		return strconv.FormatUint(u/day, 10) + "d"
	case u > hour:
		return strconv.FormatUint(u/hour, 10) + "h"
	case u > minute:
		return strconv.FormatUint(u/minute, 10) + "m"
	case u > second:
		return strconv.FormatUint(u/second, 10) + "s"
	default:
		return "0s"
	}
}

func date(ts time.Time) string {
	return ts.Format("2006-01-02")
}

func truncate(length int, v any) string {
	sv := strval(v)
	if len(sv) < length-3 {
		return sv
	}

	return sv[:length-3] + "..."
}

func join(sep string, v any) string {
	return strings.Join(stringslice(v), sep)
}

func stringslice(v any) []string {
	switch v := v.(type) {
	case []string:
		return v
	case []interface{}:
		res := make([]string, 0, len(v))
		for _, s := range v {
			if s == nil {
				continue
			}
			res = append(res, strval(s))
		}

		return res
	default:
		val := reflect.ValueOf(v)
		switch val.Kind() { //nolint:exhaustive
		case reflect.Array, reflect.Slice:
			l := val.Len()
			res := make([]string, 0, l)
			for i := 0; i < l; i++ {
				value := val.Index(i).Interface()
				if value == nil {
					continue
				}
				res = append(res, strval(value))
			}

			return res
		default:
			if v == nil {
				return []string{}
			}

			return []string{strval(v)}
		}
	}
}

func strval(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	case error:
		return v.Error()
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

func funcMap(ctx context.Context, kv kvstore) template.FuncMap {
	return template.FuncMap{
		FuncGet:           get(ctx, kv),
		FuncGetPassword:   getPassword(ctx, kv),
		FuncGetValue:      getValue(ctx, kv),
		FuncGetValues:     getValues(ctx, kv),
		FuncBlake3:        blake3sum(),
		FuncArgon2i:       argon2iFunc(),
		FuncArgon2id:      argon2idFunc(),
		FuncJoin:          join,
		FuncRoundDuration: roundDuration,
		FuncDate:          date,
		FuncTruncate:      truncate,
	}
}

// PublicFuncMap returns a template.FuncMap with useful template functions.
func PublicFuncMap() template.FuncMap {
	return template.FuncMap{
		FuncBlake3:        blake3sum(),
		FuncArgon2i:       argon2iFunc(),
		FuncArgon2id:      argon2idFunc(),
		FuncJoin:          join,
		FuncRoundDuration: roundDuration,
		FuncDate:          date,
		FuncTruncate:      truncate,
	}
}
