package masker_test

import (
	"errors"
	"fmt"
	"strings"

	"github.com/icntswm/go-masker"
)

func ExampleNew() {
	m, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}

	value, err := m.MaskValue("password", "synthetic-secret")
	if err != nil {
		panic(err)
	}
	fmt.Println(value)
	// Output: [REDACTED]
}

func ExampleMasker_MaskJSON() {
	m, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}

	masked, err := m.MaskJSON([]byte(`{"email":"alice@example.com","token":"synthetic-secret","count":42}`))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(masked))
	// Output: {"count":42,"email":"a***@example.com","token":"[REDACTED]"}
}

func ExampleMasker_MaskJSONValue() {
	m, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}
	out, err := m.MaskJSONValue(map[string]any{"user": "alice", "password": "s3cret", "attempts": 3})
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))
	// Output: {"attempts":"3","password":"[REDACTED]","user":"alice"}
}

func ExampleWithPreserveSafeTypes() {
	m, err := masker.New(masker.DefaultPolicy(), masker.WithPreserveSafeTypes())
	if err != nil {
		panic(err)
	}

	masked, err := m.MaskAny(map[string]any{"enabled": true, "count": 3})
	if err != nil {
		panic(err)
	}
	value := masked.(map[string]any)
	fmt.Printf("%T %T %v %v\n", value["enabled"], value["count"], value["enabled"], value["count"])
	// Output: bool int true 3
}

func ExampleMasker_MaskAny_errors() {
	m, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}

	masked, err := m.MaskAny(func() {})
	var maskErr *masker.MaskError
	fmt.Println(masked, errors.As(err, &maskErr), maskErr.Code)
	// Output: [REDACTED] true unsupported_type
}

func ExampleNewRule() {
	rule, err := masker.NewRule("prefix", func(input masker.RuleInput) (string, error) {
		return "masked-" + input.Redaction, nil
	})
	if err != nil {
		panic(err)
	}

	m, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}
	masked, err := m.MaskString("synthetic-secret", rule)
	if err != nil {
		panic(err)
	}
	fmt.Println(masked)
	// Output: masked-[REDACTED]
}

func ExamplePolicyFunc() {
	policy := masker.PolicyFunc(func(field masker.Field) (masker.Decision, error) {
		if field.Key == "session_id" {
			return masker.Decision{Rule: masker.FullRule()}, nil
		}
		return masker.Decision{}, nil
	})
	m, err := masker.New(policy)
	if err != nil {
		panic(err)
	}
	masked, err := m.MaskValue("session_id", "synthetic-session")
	if err != nil {
		panic(err)
	}
	fmt.Println(masked)
	// Output: [REDACTED]
}

func Example_structTags() {
	type payload struct {
		Password string `mask:"password"`
		Name     string `json:"name"`
	}

	m, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}
	masked, err := m.MaskAny(payload{Password: "synthetic-secret", Name: "alice"})
	if err != nil {
		panic(err)
	}
	values := masked.(map[string]any)
	fmt.Println(values["Password"], values["name"])
	// Output: [REDACTED] alice
}

func ExampleMasker_MaskString() {
	m, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}

	for _, c := range []struct {
		rule  masker.Rule
		value string
	}{
		{masker.EmailRule(), "alice@example.com"},
		{masker.PhoneRule(), "+1 (555) 123-4567"},
		{masker.CardRule(), "4111 1111 1111 1111"},
		{masker.IDRule(), "user-8891"},
		{masker.TokenRule(), "synthetic-token"},
	} {
		masked, err := m.MaskString(c.value, c.rule)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%-8s %s\n", c.rule.Name(), masked)
	}

	// Output:
	// email    a***@example.com
	// phone    +* (***) ***-4567
	// card     **** **** **** 1111
	// id       *****8891
	// token    [REDACTED]
}

func ExampleDefaultBindings() {
	// The built-in key bindings are public and inspectable; DefaultBindings
	// returns a copy that can be extended without touching the defaults.
	for _, binding := range masker.DefaultBindings() {
		fmt.Printf("%-8s %v\n", binding.Rule.Name(), binding.Keys)
	}

	// Output:
	// password [password passwd passphrase]
	// token    [token access_token refresh_token api_key apikey secret client_secret id_token private_key session_id credentials auth_token]
	// email    [email e-mail]
	// phone    [phone phone_number mobile]
	// id       [id user_id customer_id]
	// card     [card card_number pan]
	// full     [authorization cookie set-cookie x-api-key x-auth-token proxy-authorization x-csrf-token cvv cvc]
}

func ExampleNewKeyPolicy() {
	policy, err := masker.NewKeyPolicy(
		masker.Binding{Keys: []string{"ssn", "tax_id"}, Rule: masker.FullRule()},
		masker.Binding{Keys: []string{"contact"}, Rule: masker.EmailRule()},
	)
	if err != nil {
		panic(err)
	}
	m, err := masker.New(policy)
	if err != nil {
		panic(err)
	}

	// Key matching is case-insensitive.
	masked, err := m.MaskJSON([]byte(`{"Tax_ID":"123-45-6789","contact":"alice@example.com","team":"core"}`))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(masked))
	// Output: {"Tax_ID":"[REDACTED]","contact":"a***@example.com","team":"core"}
}

func ExampleChain() {
	// The first policy with an opinion wins; the defaults act as a fallback.
	tenant := masker.PolicyFunc(func(field masker.Field) (masker.Decision, error) {
		if field.Key == "tenant" {
			return masker.Decision{Rule: masker.FullRule()}, nil
		}
		return masker.Decision{}, nil
	})
	m, err := masker.New(masker.Chain(tenant, masker.DefaultPolicy()))
	if err != nil {
		panic(err)
	}

	masked, err := m.MaskJSON([]byte(`{"tenant":"acme","password":"synthetic-secret","region":"eu"}`))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(masked))
	// Output: {"password":"[REDACTED]","region":"eu","tenant":"[REDACTED]"}
}

func ExampleWithRedaction() {
	m, err := masker.New(masker.DefaultPolicy(), masker.WithRedaction("***"))
	if err != nil {
		panic(err)
	}

	masked, err := m.MaskJSON([]byte(`{"password":"synthetic-secret"}`))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(masked))
	// Output: {"password":"***"}
}

func ExampleWithStructTag() {
	type payload struct {
		Token string `secret:"token"`
		Team  string
	}

	m, err := masker.New(masker.DefaultPolicy(), masker.WithStructTag("secret"))
	if err != nil {
		panic(err)
	}
	masked, err := m.MaskAny(payload{Token: "synthetic-token", Team: "core"})
	if err != nil {
		panic(err)
	}
	values := masked.(map[string]any)
	fmt.Println(values["Token"], values["Team"])
	// Output: [REDACTED] core
}

func ExampleWithTagRule() {
	type payload struct {
		ID string `mask:"last2"`
	}

	last2, err := masker.NewRule("last2", func(input masker.RuleInput) (string, error) {
		runes := []rune(input.Value)
		if len(runes) < 2 {
			return "**", nil
		}
		return string(runes[len(runes)-2:]), nil
	})
	if err != nil {
		panic(err)
	}

	m, err := masker.New(masker.DefaultPolicy(), masker.WithTagRule("last2", last2))
	if err != nil {
		panic(err)
	}
	masked, err := m.MaskAny(payload{ID: "customer-8891"})
	if err != nil {
		panic(err)
	}
	values := masked.(map[string]any)
	fmt.Println(values["ID"])
	// Output: 91
}

func ExampleMasker_MaskField() {
	m, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}

	// The same key and value under two sources. Transport metadata is treated
	// paranoidly: a header is fully redacted even when the policy rule is
	// partial.
	body, err := m.MaskField(masker.Field{Key: "email", Source: masker.SourceJSON}, "alice@example.com")
	if err != nil {
		panic(err)
	}
	header, err := m.MaskField(masker.Field{Key: "email", Source: masker.SourceHeader}, "alice@example.com")
	if err != nil {
		panic(err)
	}
	fmt.Println(body)
	fmt.Println(header)

	// Output:
	// a***@example.com
	// [REDACTED]
}

func ExampleMasker_MaskJSONReader() {
	m, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}

	// The reader is read to completion and is not closed by the library.
	body := strings.NewReader(`{"api_key":"synthetic-key","page":2}`)
	masked, err := m.MaskJSONReader(body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(masked))
	// Output: {"api_key":"[REDACTED]","page":2}
}

func ExampleWithMaxDepth() {
	// Limits are fail-closed: exceeding one discards the whole result rather
	// than returning a partially masked document.
	m, err := masker.New(masker.DefaultPolicy(), masker.WithMaxDepth(1))
	if err != nil {
		panic(err)
	}

	masked, err := m.MaskJSON([]byte(`{"outer":{"inner":"value"}}`))
	fmt.Println(string(masked), errors.Is(err, masker.ErrDepthLimit))
	// Output: "[REDACTED]" true
}

func ExampleWithMaxNodes() {
	m, err := masker.New(masker.DefaultPolicy(), masker.WithMaxNodes(3))
	if err != nil {
		panic(err)
	}

	masked, err := m.MaskJSON([]byte(`{"a":1,"b":2,"c":3,"d":4}`))
	fmt.Println(string(masked), errors.Is(err, masker.ErrNodeLimit))
	// Output: "[REDACTED]" true
}

func ExampleWithMaxInputBytes() {
	m, err := masker.New(masker.DefaultPolicy(), masker.WithMaxInputBytes(16))
	if err != nil {
		panic(err)
	}

	masked, err := m.MaskJSON([]byte(`{"password":"synthetic-secret"}`))
	fmt.Println(string(masked), errors.Is(err, masker.ErrInputLimit))
	// Output: "[REDACTED]" true
}

func Example_omitField() {
	// A policy can drop a field entirely instead of replacing its value.
	policy := masker.PolicyFunc(func(field masker.Field) (masker.Decision, error) {
		if field.Key == "internal_note" {
			return masker.Decision{Omit: true}, nil
		}
		return masker.Decision{}, nil
	})
	m, err := masker.New(policy)
	if err != nil {
		panic(err)
	}

	masked, err := m.MaskJSON([]byte(`{"internal_note":"debug only","user":"alice"}`))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(masked))
	// Output: {"user":"alice"}
}

func Example_cycleDetection() {
	m, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}

	node := map[string]any{"name": "root"}
	node["self"] = node

	masked, err := m.MaskAny(node)
	fmt.Println(masked, errors.Is(err, masker.ErrCycle))
	// Output: [REDACTED] true
}

func Example_errorCategories() {
	m, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}

	_, err = m.MaskJSON([]byte(`{"broken":`))

	// errors.Is matches the category, errors.As reaches the safe details.
	// Errors never carry the original value.
	var detail *masker.MaskError
	fmt.Println(errors.Is(err, masker.ErrInvalidJSON), errors.As(err, &detail), detail.Code, detail.Operation)
	// Output: true true invalid_json mask_json
}

func ExampleMasker_MaskValue_embeddedDocuments() {
	m, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}

	// A callback URL and a request body carried as plain strings are masked
	// as the documents they hold: the field names never appear in a
	// sensitive-key list, but the values speak for themselves.
	callback, err := m.MaskValue("note", "https://u:dummy@h/cb?token=dummy-token")
	if err != nil {
		panic(err)
	}
	body, err := m.MaskValue("note", `{"password":"dummy-secret"}`)
	if err != nil {
		panic(err)
	}
	fmt.Println(callback)
	fmt.Println(body)
	// Output:
	// https://%5BREDACTED%5D@h/cb?token=%5BREDACTED%5D
	// {"password":"[REDACTED]"}
}

func ExampleWithoutEmbeddedDocuments() {
	value := "https://u:dummy@h/cb?token=dummy-token"

	m, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}
	masked, err := m.MaskValue("note", value)
	if err != nil {
		panic(err)
	}

	// Without embedded documents the URL is no longer parsed, but the text
	// detectors still find its userinfo and the token=... pair.
	text, err := masker.New(masker.DefaultPolicy(), masker.WithoutEmbeddedDocuments())
	if err != nil {
		panic(err)
	}
	asText, err := text.MaskValue("note", value)
	if err != nil {
		panic(err)
	}

	fmt.Println(masked)
	fmt.Println(asText)
	// Output:
	// https://%5BREDACTED%5D@h/cb?token=%5BREDACTED%5D
	// https://[REDACTED]@h/cb?token=[REDACTED]
}

func ExampleWithoutValueInspection() {
	m, err := masker.New(masker.DefaultPolicy(), masker.WithoutValueInspection())
	if err != nil {
		panic(err)
	}
	leaked, err := m.MaskValue("note", "retry with password=dummy-pass")
	if err != nil {
		panic(err)
	}

	fmt.Println(leaked)
	// Output:
	// retry with password=dummy-pass
}

func ExampleMasker_MaskValue_secretsInText() {
	m, err := masker.New(masker.DefaultPolicy())
	if err != nil {
		panic(err)
	}
	for _, text := range []string{
		"login failed: password=dummy-pass",
		"upstream said: Bearer dummy-token-placeholder rejected",
		"dial postgres://app:dummy@db:5432/app failed",
	} {
		masked, err := m.MaskValue("message", text)
		if err != nil {
			panic(err)
		}
		fmt.Println(masked)
	}
	// Output:
	// login failed: password=[REDACTED]
	// upstream said: Bearer [REDACTED] rejected
	// dial postgres://[REDACTED]@db:5432/app failed
}

func ExampleWithoutTextDetectors() {
	m, err := masker.New(masker.DefaultPolicy(), masker.WithoutTextDetectors())
	if err != nil {
		panic(err)
	}
	masked, err := m.MaskValue("message", "login failed: password=dummy-pass")
	if err != nil {
		panic(err)
	}

	fmt.Println(masked)
	// Output:
	// login failed: password=dummy-pass
}

func ExampleWithCardNumberDetection() {
	m, err := masker.New(masker.DefaultPolicy(), masker.WithCardNumberDetection())
	if err != nil {
		panic(err)
	}
	// 4111 1111 1111 1111 is the well-known example Visa number.
	masked, err := m.MaskValue("message", "paid with 4111 1111 1111 1111")
	if err != nil {
		panic(err)
	}

	fmt.Println(masked)
	// Output:
	// paid with **** **** **** 1111
}

func ExampleWithAWSKeyIDDetection() {
	m, err := masker.New(masker.DefaultPolicy(), masker.WithAWSKeyIDDetection())
	if err != nil {
		panic(err)
	}
	masked, err := m.MaskValue("message", "rotated AKIADUMMYEXAMPLE0000")
	if err != nil {
		panic(err)
	}

	fmt.Println(masked)
	// Output:
	// rotated [REDACTED]
}
