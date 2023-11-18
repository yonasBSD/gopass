package tpl

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/gopasspw/gopass/internal/pwschemes/argon2i"
	"github.com/gopasspw/gopass/internal/pwschemes/argon2id"
	"github.com/gopasspw/gopass/pkg/gopass"
	"github.com/gopasspw/gopass/pkg/gopass/secrets/secparse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Example() { //nolint:testableexamples
	ctx := context.Background()
	tpl := `Password-value of existing entry: {{ getpw "foo" }}
Password-value of the new entry: {{ .Content }}
Blake3sum of the new password: {{ .Content | blake3sum }}
Argon2i of the new password: {{ .Content | argon2i }}
Argon2id of the new password: {{ .Content | argon2id }}
`
	kv := kvMock{}

	// Arguments: context, template string, name of the secret, generated password, kv store
	buf, err := Execute(ctx, tpl, "example", []byte("bar"), kv)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(buf))
}

type kvMock struct{}

func (k kvMock) Get(ctx context.Context, key string) (gopass.Secret, error) {
	return secparse.Parse([]byte("barfoo\n---\nbarkey: barvalue\n")) //nolint:wrapcheck
}

//nolint:gocognit
func TestVars(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	kv := kvMock{}

	for _, tc := range []struct {
		Template   string
		Name       string
		Content    []byte
		Output     string
		OutputFunc func(string) error
		ShouldFail bool
	}{
		{
			Template: "{{.Dir}}",
			Name:     "testdir",
			Content:  []byte("foobar"),
			Output:   ".",
		},
		{
			Template: "{{.Path}}",
			Name:     "testdir",
			Content:  []byte("foobar"),
			Output:   "testdir",
		},
		{
			Template: "{{.DirName}}",
			Name:     "foo/bar/baz",
			Content:  []byte("foobar"),
			Output:   "bar",
		},
		{
			Template: "{{.Name}}",
			Name:     "testdir",
			Content:  []byte("foobar"),
			Output:   "testdir",
		},
		{
			Template: "{{.Content}}",
			Name:     "testdir",
			Content:  []byte("foobar"),
			Output:   "foobar",
		},
		{
			Template: `{{getpw "testdir"}}`,
			Name:     "testdir",
			Content:  []byte("foobar"),
			Output:   "barfoo",
		},
		{
			Template: `{{get "testdir"}}`,
			Name:     "testdir",
			Content:  []byte("foobar"),
			Output:   "barfoo\n---\nbarkey: barvalue\n",
		},
		{
			Template: `{{getpw "testdir"}}`,
			Name:     "testdir",
			Content:  []byte("foobar"),
			Output:   "barfoo",
		},
		{
			Template: `{{getval "testdir" "barkey"}}`,
			Name:     "testdir",
			Content:  []byte("foobar"),
			Output:   "barvalue",
		},
		{
			Template:   `{{getval "testdir" "barkeyINVALID"}}`,
			Name:       "testdir",
			Content:    []byte("foobar"),
			Output:     "",
			ShouldFail: true,
		},
		{
			Template: `{{getvals "testdir" "barkey"}}`,
			Name:     "testdir",
			Content:  []byte("foobar"),
			Output:   "[barvalue]",
		},
		{
			Template:   `{{|}}`,
			Name:       "testdir",
			Content:    []byte("foobar"),
			Output:     "",
			ShouldFail: true,
		},
		{
			Template: "{{.Content | argon2i \"64\"}}",
			Name:     "testdir",
			Content:  []byte("foobar"),
			OutputFunc: func(s string) error {
				if !strings.HasPrefix(s, "{ARGON2I}") {
					return fmt.Errorf("wrong prefix: %s", s)
				}

				ok, err := argon2i.Validate("foobar", s)
				if err != nil {
					return fmt.Errorf("can't validate: %w", err)
				}

				if !ok {
					return fmt.Errorf("hash mismatch")
				}

				return nil
			},
		},
		{
			Template: "{{.Content | argon2id \"256\"}}",
			Name:     "testdir",
			Content:  []byte("foobar"),
			OutputFunc: func(s string) error {
				if !strings.HasPrefix(s, "{ARGON2ID}") {
					return fmt.Errorf("wrong prefix: %s", s)
				}

				ok, err := argon2id.Validate("foobar", s)
				if err != nil {
					return fmt.Errorf("can't validate: %w", err)
				}

				if !ok {
					return fmt.Errorf("hash mismatch")
				}

				return nil
			},
		},
		{
			Template:   "{{ argon2id }}",
			Name:       "testdir",
			Content:    []byte("foobar"),
			ShouldFail: true,
		},
	} {
		tc := tc
		t.Run(tc.Template, func(t *testing.T) {
			t.Parallel()

			buf, err := Execute(ctx, tc.Template, tc.Name, tc.Content, kv)
			if tc.ShouldFail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if tc.OutputFunc != nil && tc.Output != "" {
				t.Error("must not set output and output func")
			}
			if tc.OutputFunc != nil {
				require.NoError(t, tc.OutputFunc(string(buf)), tc.Template)
			} else {
				assert.Equal(t, tc.Output, string(buf), tc.Template)
			}
		})
	}
}
