package masker

import "testing"

func TestEmbeddedDocumentsSmoke(t *testing.T) {
	m := newTestMasker(t)
	tests := []struct {
		name  string
		key   string
		value string
		want  string
	}{
		{
			name:  "url userinfo",
			key:   "url",
			value: "https://u:dummy@host/cb",
			want:  "https://%5BREDACTED%5D@host/cb",
		},
		{
			name:  "json body",
			key:   "body",
			value: `{"password":"dummy-secret"}`,
			want:  `{"password":"[REDACTED]"}`,
		},
		{
			name:  "form",
			key:   "form",
			value: "user=a&password=dummy",
			want:  "password=%5BREDACTED%5D&user=a",
		},
		{
			name:  "plain text",
			key:   "note",
			value: "hello world",
			want:  "hello world",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := m.MaskValue(test.key, test.value)
			if err != nil {
				t.Fatal(err)
			}
			masked, ok := result.(string)
			if !ok {
				t.Fatalf("result is not a string: %#v", result)
			}
			if masked != test.want {
				t.Fatalf("unexpected result: got %q want %q", masked, test.want)
			}
		})
	}
}
