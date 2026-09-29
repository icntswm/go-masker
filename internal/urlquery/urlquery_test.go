package urlquery

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

func TestMask(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		drop    []string
		want    string
		wantErr error
	}{
		{
			name: "sorts keys and preserves duplicate order",
			raw:  "z=last&token=one&keep=first&token=two&keep=second&a=first",
			want: "a=first&keep=first&keep=second&token=MARK&token=MARK&z=last",
		},
		{
			name: "unescapes and re-encodes values",
			raw:  "b=hello+world&a=1&x=%2F%3D",
			want: "a=1&b=hello+world&x=%2F%3D",
		},
		{
			name: "escapes keys and values of the masked output",
			raw:  "k%26y=a%3Db",
			want: "k%26y=a%3Db",
		},
		{
			name: "skips empty parts and keys",
			raw:  "&&b&=ignored&a=&",
			want: "a=&b=",
		},
		{
			name: "drops pairs the callback omits",
			raw:  "a=1&secret=2&b=3",
			drop: []string{"secret"},
			want: "a=1&b=3",
		},
		{
			name: "empty when every pair is dropped",
			raw:  "secret=2&secret=3",
			drop: []string{"secret"},
			want: "",
		},
		{
			name:    "rejects semicolon",
			raw:     "a=1;b=2",
			wantErr: ErrInvalidQuery,
		},
		{
			name:    "rejects semicolon in an otherwise empty part",
			raw:     "a=1&;",
			wantErr: ErrInvalidQuery,
		},
		{
			name:    "rejects invalid escape",
			raw:     "a=%zz",
			wantErr: ErrInvalidQuery,
		},
		{
			name: "empty input yields empty output",
			raw:  "",
			want: "",
		},
	}

	markToken := "MARK"

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dropped := map[string]bool{}
			for _, key := range test.drop {
				dropped[key] = true
			}
			mask := func(key, value string) (string, bool, error) {
				if dropped[key] {
					return "", false, nil
				}
				if key == "token" {
					return markToken, true, nil
				}
				return value, true, nil
			}

			got, err := Mask(test.raw, mask)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("want error %v, got %v", test.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("masked query mismatch: got %q want %q", got, test.want)
			}
		})
	}
}

func TestMaskPassesCallbackErrorThrough(t *testing.T) {
	sentinel := errors.New("rule failure")
	got, err := Mask("a=1", func(key, value string) (string, bool, error) {
		return "", false, sentinel
	})
	if !errors.Is(err, sentinel) || got != "" {
		t.Fatalf("callback error not passed through: got %q err %v", got, err)
	}
}

func TestMaskDoesNotAmplifySeparators(t *testing.T) {
	// A separator-only query carries no pairs at all, so the scratch slice must
	// not scale with the input length.
	raw := strings.Repeat("&", 1<<20)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	masked, err := Mask(raw, func(key, value string) (string, bool, error) {
		return value, true, nil
	})
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if masked != "" {
		t.Fatalf("unexpected query output: %q", masked)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > uint64(len(raw)) {
		t.Fatalf("query masking allocated %d bytes for %d bytes of separators", allocated, len(raw))
	}
}
