// Package detect finds secrets inside free text: tokens recognized by their
// shape, and key=value pairs whose key a policy may judge.
//
// The package only locates; it never masks. Every function works on raw
// bytes in one forward pass, without regular expressions, and allocates
// nothing for text in which nothing is found.
package detect

// Set selects the opt-in detectors; the default detectors always run.
type Set struct {
	// Cards finds payment card numbers that pass the Luhn check.
	Cards bool
	// AWSKeyIDs finds AWS access key ids.
	AWSKeyIDs bool
}

// Kind names the detector that found a Span.
type Kind uint8

const (
	// KindBearer is the token after the word Bearer or Basic.
	KindBearer Kind = iota + 1
	// KindPEM is the body of a PEM private key block.
	KindPEM
	// KindJWT is a JSON Web Token.
	KindJWT
	// KindProviderToken is an access token with a known provider prefix.
	KindProviderToken
	// KindURLUserinfo is the userinfo of a URL written inside text.
	KindURLUserinfo
	// KindCard is a payment card number.
	KindCard
	// KindAWSKeyID is an AWS access key id.
	KindAWSKeyID
)

// Span is a secret found by its shape: s[Start:End].
type Span struct {
	Start, End int
	Kind       Kind
}

// Pair is a key=value candidate: the key is s[KeyStart:KeyEnd] and the value
// s[ValueStart:ValueEnd], without surrounding quotes.
type Pair struct {
	KeyStart, KeyEnd, ValueStart, ValueEnd int
}

// Candidate reports, without allocating, whether Find would return anything
// for s. It is exact, not a prefilter: callers pay for a path only when the
// text really holds something.
func Candidate[T ~string | ~[]byte](s T, set Set) bool {
	_, _, found := scan(s, set, true)
	return found
}

// Find returns every span and every key=value pair in s, each list in
// ascending start order. It returns nil slices, without allocating, when
// nothing is found. A span is never searched for inside another span, but
// the value of a pair is searched, so a token survives an undecided key;
// spans and pairs may therefore overlap, and the caller resolves that.
func Find(s string, set Set) (spans []Span, pairs []Pair) {
	spans, pairs, _ = scan(s, set, false)
	return spans, pairs
}

// scan runs every detector at each position. With first set it stops at the
// first hit and appends nothing.
func scan[T ~string | ~[]byte](s T, set Set, first bool) (spans []Span, pairs []Pair, found bool) {
	var run valueRun
	for index := 0; index < len(s); {
		if span, ok := matchSpan(s, index, set); ok {
			if first {
				return nil, nil, true
			}
			spans = append(spans, span)
			found = true
			// matchSpan never returns an empty span that ends before index.
			index = max(span.End, index+1)
			continue
		}
		if pair, ok := matchPair(s, index, &run); ok {
			if first {
				return nil, nil, true
			}
			pairs = append(pairs, pair)
			found = true
			index = pair.ValueStart
			continue
		}
		index++
	}
	return spans, pairs, found
}

func matchSpan[T ~string | ~[]byte](s T, index int, set Set) (Span, bool) {
	switch char := s[index]; {
	case char == '-':
		return matchPEM(s, index)
	case char >= '0' && char <= '9':
		if set.Cards {
			return matchCard(s, index)
		}
		return Span{}, false
	case !isLetter(char):
		return Span{}, false
	}
	if span, ok := matchBearer(s, index); ok {
		return span, true
	}
	if span, ok := matchJWT(s, index); ok {
		return span, true
	}
	if span, ok := matchProviderToken(s, index); ok {
		return span, true
	}
	if set.AWSKeyIDs {
		if span, ok := matchAWSKeyID(s, index); ok {
			return span, true
		}
	}
	return matchURLUserinfo(s, index)
}

func isLetter(char byte) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z'
}

func isDigit(char byte) bool {
	return char >= '0' && char <= '9'
}

func isAlnum(char byte) bool {
	return isLetter(char) || isDigit(char)
}

func isWord(char byte) bool {
	return isAlnum(char) || char == '_'
}

func isBase64URL(char byte) bool {
	return isWord(char) || char == '-'
}

func isToken68(char byte) bool {
	return isAlnum(char) || char == '-' || char == '.' || char == '_' || char == '~' || char == '+' || char == '/'
}

func isKeyChar(char byte) bool {
	return isWord(char) || char == '.' || char == '-'
}

func isSchemeChar(char byte) bool {
	return isAlnum(char) || char == '+' || char == '-' || char == '.'
}

// isSpace treats every control byte as white space: text is split on it, and
// no detector's alphabet contains one.
func isSpace(char byte) bool {
	return char <= ' ' || char == 0x7f
}

func lower(char byte) byte {
	if char >= 'A' && char <= 'Z' {
		return char + 'a' - 'A'
	}
	return char
}

// hasPrefixAt reports whether s[index:] starts with prefix.
func hasPrefixAt[T ~string | ~[]byte](s T, index int, prefix string) bool {
	if len(s)-index < len(prefix) {
		return false
	}
	for offset := range len(prefix) {
		if s[index+offset] != prefix[offset] {
			return false
		}
	}
	return true
}

// hasFoldPrefixAt is hasPrefixAt ignoring ASCII case; prefix is lowercase.
func hasFoldPrefixAt[T ~string | ~[]byte](s T, index int, prefix string) bool {
	if len(s)-index < len(prefix) {
		return false
	}
	for offset := range len(prefix) {
		if lower(s[index+offset]) != prefix[offset] {
			return false
		}
	}
	return true
}

// runEnd returns the end of the run of bytes accepted by class from index.
func runEnd[T ~string | ~[]byte](s T, index int, class func(byte) bool) int {
	for index < len(s) && class(s[index]) {
		index++
	}
	return index
}

// boundedBefore reports whether the byte before index, if any, is outside
// class, so a match cannot start in the middle of a longer word.
func boundedBefore[T ~string | ~[]byte](s T, index int, class func(byte) bool) bool {
	return index == 0 || !class(s[index-1])
}
