package detect

// matchBearer finds the credential after an HTTP authentication scheme
// written in text: "Bearer <token>" or "Basic <token>". A token of lowercase
// letters only is prose ("bearer of news"), not a credential.
func matchBearer[T ~string | ~[]byte](s T, index int) (Span, bool) {
	if !boundedBefore(s, index, isWord) {
		return Span{}, false
	}
	var word int
	switch {
	case hasFoldPrefixAt(s, index, "bearer"):
		word = len("bearer")
	case hasFoldPrefixAt(s, index, "basic"):
		word = len("basic")
	default:
		return Span{}, false
	}
	start := index + word
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	if start == index+word {
		return Span{}, false
	}
	end := runEnd(s, start, isToken68)
	for end < len(s) && s[end] == '=' {
		end++
	}
	if end-start < 8 {
		return Span{}, false
	}
	for offset := start; offset < end; offset++ {
		if char := s[offset]; char < 'a' || char > 'z' {
			return Span{start, end, KindBearer}, true
		}
	}
	return Span{}, false
}

// matchPEM finds the body of a PEM private key block. The BEGIN and END
// lines stay visible; a block cut off before its END line is masked to the
// end of the text.
func matchPEM[T ~string | ~[]byte](s T, index int) (Span, bool) {
	const begin = "-----BEGIN "
	if !hasPrefixAt(s, index, begin) {
		return Span{}, false
	}
	labelStart := index + len(begin)
	labelEnd := labelStart
	for labelEnd < len(s) && labelEnd-labelStart <= 64 && !hasPrefixAt(s, labelEnd, "-----") {
		if s[labelEnd] == '\n' {
			return Span{}, false
		}
		labelEnd++
	}
	if !hasPrefixAt(s, labelEnd, "-----") || !containsAt(s, labelStart, labelEnd, "PRIVATE KEY") {
		return Span{}, false
	}
	bodyStart := labelEnd + len("-----")
	for footer := bodyStart; footer < len(s); footer++ {
		if !hasPrefixAt(s, footer, "-----END ") {
			continue
		}
		label := footer + len("-----END ")
		if !sameBytes(s, label, labelStart, labelEnd-labelStart) ||
			!hasPrefixAt(s, label+labelEnd-labelStart, "-----") {
			continue
		}
		if footer == bodyStart {
			return Span{}, false
		}
		return Span{bodyStart, footer, KindPEM}, true
	}
	if bodyStart == len(s) {
		return Span{}, false
	}
	return Span{bodyStart, len(s), KindPEM}, true
}

// containsAt reports whether s[start:end] contains needle.
func containsAt[T ~string | ~[]byte](s T, start, end int, needle string) bool {
	for index := start; index+len(needle) <= end; index++ {
		if hasPrefixAt(s, index, needle) {
			return true
		}
	}
	return false
}

// sameBytes reports whether s[at:at+n] equals s[from:from+n].
func sameBytes[T ~string | ~[]byte](s T, at, from, n int) bool {
	if at+n > len(s) {
		return false
	}
	for offset := range n {
		if s[at+offset] != s[from+offset] {
			return false
		}
	}
	return true
}

// matchJWT finds a JSON Web Token: two base64url segments that both decode
// to a JSON object, hence "eyJ", and a signature that may be empty.
func matchJWT[T ~string | ~[]byte](s T, index int) (Span, bool) {
	if !boundedBefore(s, index, isJWTChar) || !hasPrefixAt(s, index, "eyJ") {
		return Span{}, false
	}
	headerEnd := runEnd(s, index, isBase64URL)
	if headerEnd-index < 10 || headerEnd >= len(s) || s[headerEnd] != '.' {
		return Span{}, false
	}
	payload := headerEnd + 1
	if !hasPrefixAt(s, payload, "eyJ") {
		return Span{}, false
	}
	payloadEnd := runEnd(s, payload, isBase64URL)
	if payloadEnd-payload < 10 || payloadEnd >= len(s) || s[payloadEnd] != '.' {
		return Span{}, false
	}
	return Span{index, runEnd(s, payloadEnd+1, isBase64URL), KindJWT}, true
}

func isJWTChar(char byte) bool {
	return isBase64URL(char) || char == '.'
}

type providerPrefix struct {
	prefix string
	class  func(byte) bool
	min    int
	exact  bool
}

func isAlnumDash(char byte) bool { return isAlnum(char) || char == '-' }

// providerPrefixes lists access tokens whose prefix names the issuer: the
// prefix is what makes them recognizable without any key around them.
var providerPrefixes = [...]providerPrefix{
	{"ghp_", isAlnum, 36, false},
	{"gho_", isAlnum, 36, false},
	{"ghu_", isAlnum, 36, false},
	{"ghs_", isAlnum, 36, false},
	{"ghr_", isAlnum, 36, false},
	{"github_pat_", isWord, 22, false},
	{"glpat-", isBase64URL, 20, false},
	{"xoxb-", isAlnumDash, 10, false},
	{"xoxp-", isAlnumDash, 10, false},
	{"xoxa-", isAlnumDash, 10, false},
	{"xoxr-", isAlnumDash, 10, false},
	{"xoxs-", isAlnumDash, 10, false},
	{"xoxe-", isAlnumDash, 10, false},
	{"sk_live_", isAlnum, 16, false},
	{"rk_live_", isAlnum, 16, false},
	{"sk_test_", isAlnum, 16, false},
	{"rk_test_", isAlnum, 16, false},
	{"AIza", isBase64URL, 35, true},
	{"npm_", isAlnum, 36, false},
}

func matchProviderToken[T ~string | ~[]byte](s T, index int) (Span, bool) {
	if !boundedBefore(s, index, isWord) {
		return Span{}, false
	}
	for _, provider := range &providerPrefixes {
		if s[index] != provider.prefix[0] || !hasPrefixAt(s, index, provider.prefix) {
			continue
		}
		start := index + len(provider.prefix)
		end := runEnd(s, start, provider.class)
		n := end - start
		if n < provider.min || provider.exact && n != provider.min {
			continue
		}
		return Span{index, end, KindProviderToken}, true
	}
	return Span{}, false
}

// matchAWSKeyID finds an AWS access key id: a four-letter type prefix and
// sixteen uppercase letters or digits.
func matchAWSKeyID[T ~string | ~[]byte](s T, index int) (Span, bool) {
	if !boundedBefore(s, index, isAlnum) {
		return Span{}, false
	}
	if !hasPrefixAt(s, index, "AKIA") && !hasPrefixAt(s, index, "ASIA") &&
		!hasPrefixAt(s, index, "ABIA") && !hasPrefixAt(s, index, "ACCA") {
		return Span{}, false
	}
	end := index + 20
	if end > len(s) || end < len(s) && isAlnum(s[end]) {
		return Span{}, false
	}
	for offset := index + 4; offset < end; offset++ {
		if char := s[offset]; (char < 'A' || char > 'Z') && !isDigit(char) {
			return Span{}, false
		}
	}
	return Span{index, end, KindAWSKeyID}, true
}

// matchURLUserinfo finds the userinfo of a URL written inside text, the
// "user:password" in "scheme://user:password@host".
func matchURLUserinfo[T ~string | ~[]byte](s T, index int) (Span, bool) {
	if !boundedBefore(s, index, isSchemeChar) {
		return Span{}, false
	}
	schemeEnd := runEnd(s, index, isSchemeChar)
	if !hasPrefixAt(s, schemeEnd, "://") {
		return Span{}, false
	}
	start := schemeEnd + len("://")
	end := start
	for end < len(s) {
		char := s[end]
		if char == '/' || char == '?' || char == '#' || char == '@' || isSpace(char) {
			break
		}
		end++
	}
	if end == start || end == len(s) || s[end] != '@' {
		return Span{}, false
	}
	return Span{start, end, KindURLUserinfo}, true
}

// matchCard finds a payment card number: 13 to 19 digits, optionally
// grouped by single spaces or dashes, that passes the Luhn check.
func matchCard[T ~string | ~[]byte](s T, index int) (Span, bool) {
	if !boundedBefore(s, index, isAlnum) {
		return Span{}, false
	}
	end, digits := index, 0
	for end < len(s) && digits <= 19 {
		if isDigit(s[end]) {
			digits++
			end++
			continue
		}
		if (s[end] == ' ' || s[end] == '-') && end+1 < len(s) && isDigit(s[end+1]) && isDigit(s[end-1]) {
			end++
			continue
		}
		break
	}
	if digits < 13 || digits > 19 || end < len(s) && isLetter(s[end]) {
		return Span{}, false
	}
	if !luhn(s, index, end) {
		return Span{}, false
	}
	return Span{index, end, KindCard}, true
}

// luhn checks the digits of s[start:end], skipping separators.
func luhn[T ~string | ~[]byte](s T, start, end int) bool {
	sum, double := 0, false
	for index := end - 1; index >= start; index-- {
		if !isDigit(s[index]) {
			continue
		}
		digit := int(s[index] - '0')
		if double {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		double = !double
	}
	return sum%10 == 0
}

// matchPair finds a "key=value" or "key: value" pair starting at index. The
// key may be quoted, as in JSON-like text; the value may be quoted, and an
// authentication scheme word ("Bearer", "Basic", "Token") takes the
// credential after it into the value.
//
// run caches the end of the last unquoted value: scanning resumes inside a
// value, and every nested pair's value ends at the same terminator, so the
// cache keeps text like "a=a=a=..." linear.
func matchPair[T ~string | ~[]byte](s T, index int, run *valueRun) (Pair, bool) {
	keyStart := index
	var keyEnd, after int
	if quote := s[index]; quote == '"' || quote == '\'' {
		keyStart = index + 1
		if keyStart >= len(s) || !isLetter(s[keyStart]) {
			return Pair{}, false
		}
		keyEnd = keyRunEnd(s, keyStart)
		if keyEnd >= len(s) || s[keyEnd] != quote {
			return Pair{}, false
		}
		after = keyEnd + 1
	} else {
		if !isLetter(s[index]) || index > 0 && (isKeyChar(s[index-1]) || s[index-1] == '/') {
			return Pair{}, false
		}
		keyEnd = keyRunEnd(s, keyStart)
		after = keyEnd
	}
	if keyEnd-keyStart > maxKeyLen {
		return Pair{}, false
	}
	after = skipBlanks(s, after)
	if after >= len(s) || s[after] != '=' && s[after] != ':' {
		return Pair{}, false
	}
	if s[after] == ':' && hasPrefixAt(s, after+1, "//") {
		return Pair{}, false
	}
	valueStart := skipBlanks(s, after+1)
	if valueStart >= len(s) {
		return Pair{}, false
	}
	if quote := s[valueStart]; quote == '"' || quote == '\'' {
		valueStart++
		valueEnd := valueStart
		for valueEnd < len(s) && s[valueEnd] != '\n' && (s[valueEnd] != quote || s[valueEnd-1] == '\\') {
			valueEnd++
		}
		if valueEnd == valueStart {
			return Pair{}, false
		}
		return Pair{keyStart, keyEnd, valueStart, valueEnd}, true
	}
	valueEnd := run.end
	if valueStart < run.start || valueStart >= run.end {
		valueEnd = runEnd(s, valueStart, isValueChar)
		*run = valueRun{valueStart, valueEnd}
	}
	if valueEnd == valueStart {
		return Pair{}, false
	}
	if isSchemeWord(s, valueStart, valueEnd) {
		credential := skipBlanks(s, valueEnd)
		if credential > valueEnd {
			if credentialEnd := runEnd(s, credential, isValueChar); credentialEnd > credential {
				valueEnd = credentialEnd
			}
		}
	}
	return Pair{keyStart, keyEnd, valueStart, valueEnd}, true
}

// valueRun is a run of value bytes, s[start:end], already measured.
type valueRun struct {
	start, end int
}

// keyRunEnd measures a key, stopping one byte past the longest accepted key
// so a long word costs no more than a short one.
func keyRunEnd[T ~string | ~[]byte](s T, index int) int {
	end := index
	for end < len(s) && end-index <= maxKeyLen && isKeyChar(s[end]) {
		end++
	}
	return end
}

const maxKeyLen = 64

func skipBlanks[T ~string | ~[]byte](s T, index int) int {
	for index < len(s) && (s[index] == ' ' || s[index] == '\t') {
		index++
	}
	return index
}

// isValueChar accepts the bytes of an unquoted value: it ends at white space
// or at punctuation that closes or separates a value in prose.
func isValueChar(char byte) bool {
	switch char {
	case ',', ';', '&', ')', ']', '}', '>', '"', '\'':
		return false
	}
	return !isSpace(char)
}

func isSchemeWord[T ~string | ~[]byte](s T, start, end int) bool {
	switch end - start {
	case len("bearer"):
		return hasFoldPrefixAt(s, start, "bearer")
	case len("basic"):
		return hasFoldPrefixAt(s, start, "basic") || hasFoldPrefixAt(s, start, "token")
	}
	return false
}
