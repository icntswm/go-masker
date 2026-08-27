package masker

import (
	"encoding/json"
	"sort"
	"unicode/utf8"
)

const (
	jsonEncoderInlineKeyDepths = 8
	jsonHex                    = "0123456789abcdef"
)

type jsonTreeEncoder struct {
	buf      []byte
	keys     [jsonEncoderInlineKeyDepths][]string
	deepKeys [][]string
}

func encodeJSONTree(value any, capacityHint int) ([]byte, bool) {
	if capacityHint < 0 {
		capacityHint = 0
	}
	encoder := jsonTreeEncoder{buf: make([]byte, 0, capacityHint)}
	if !encoder.appendValue(value, 0) {
		return nil, false
	}
	return encoder.buf, true
}

func (e *jsonTreeEncoder) appendValue(value any, objectDepth int) bool {
	switch typed := value.(type) {
	case nil:
		e.buf = append(e.buf, "null"...)
	case bool:
		if typed {
			e.buf = append(e.buf, "true"...)
		} else {
			e.buf = append(e.buf, "false"...)
		}
	case string:
		e.buf = appendJSONString(e.buf, typed)
	case json.Number:
		number := typed.String()
		if !validJSONNumber(number) {
			return false
		}
		e.buf = append(e.buf, number...)
	case map[string]any:
		if typed == nil {
			e.buf = append(e.buf, "null"...)
			return true
		}
		keys := e.objectKeys(objectDepth, len(typed))
		index := 0
		for key := range typed {
			keys[index] = key
			index++
		}
		sort.Strings(keys)

		e.buf = append(e.buf, '{')
		for index, key := range keys {
			if index > 0 {
				e.buf = append(e.buf, ',')
			}
			e.buf = appendJSONString(e.buf, key)
			e.buf = append(e.buf, ':')
			if !e.appendValue(typed[key], objectDepth+1) {
				return false
			}
		}
		e.buf = append(e.buf, '}')
	case []any:
		if typed == nil {
			e.buf = append(e.buf, "null"...)
			return true
		}
		e.buf = append(e.buf, '[')
		for index, item := range typed {
			if index > 0 {
				e.buf = append(e.buf, ',')
			}
			if !e.appendValue(item, objectDepth) {
				return false
			}
		}
		e.buf = append(e.buf, ']')
	default:
		return false
	}
	return true
}

func (e *jsonTreeEncoder) objectKeys(depth, size int) []string {
	if depth < len(e.keys) {
		if cap(e.keys[depth]) < size {
			e.keys[depth] = make([]string, size)
		}
		return e.keys[depth][:size]
	}

	deepDepth := depth - len(e.keys)
	if deepDepth >= len(e.deepKeys) {
		e.deepKeys = append(e.deepKeys, make([][]string, deepDepth-len(e.deepKeys)+1)...)
	}
	if cap(e.deepKeys[deepDepth]) < size {
		e.deepKeys[deepDepth] = make([]string, size)
	}
	return e.deepKeys[deepDepth][:size]
}

func appendJSONString(dst []byte, src string) []byte {
	dst = append(dst, '"')
	start := 0
	for index := 0; index < len(src); {
		if char := src[index]; char < utf8.RuneSelf {
			if char >= 0x20 && char != '\\' && char != '"' && char != '<' && char != '>' && char != '&' {
				index++
				continue
			}
			dst = append(dst, src[start:index]...)
			switch char {
			case '\\', '"':
				dst = append(dst, '\\', char)
			case '\b':
				dst = append(dst, '\\', 'b')
			case '\f':
				dst = append(dst, '\\', 'f')
			case '\n':
				dst = append(dst, '\\', 'n')
			case '\r':
				dst = append(dst, '\\', 'r')
			case '\t':
				dst = append(dst, '\\', 't')
			default:
				dst = append(dst, '\\', 'u', '0', '0', jsonHex[char>>4], jsonHex[char&0x0f])
			}
			index++
			start = index
			continue
		}

		r, size := utf8.DecodeRuneInString(src[index:])
		if r == utf8.RuneError && size == 1 {
			dst = append(dst, src[start:index]...)
			dst = append(dst, `\ufffd`...)
			index++
			start = index
			continue
		}
		if r == '\u2028' || r == '\u2029' {
			dst = append(dst, src[start:index]...)
			dst = append(dst, '\\', 'u', '2', '0', '2', jsonHex[r&0x0f])
			index += size
			start = index
			continue
		}
		index += size
	}
	dst = append(dst, src[start:]...)
	dst = append(dst, '"')
	return dst
}

func validJSONNumber[T ~string | ~[]byte](number T) bool {
	if len(number) == 0 {
		return false
	}
	if number[0] == '-' {
		number = number[1:]
		if len(number) == 0 {
			return false
		}
	}

	switch {
	case number[0] == '0':
		number = number[1:]
	case '1' <= number[0] && number[0] <= '9':
		number = number[1:]
		for len(number) > 0 && '0' <= number[0] && number[0] <= '9' {
			number = number[1:]
		}
	default:
		return false
	}

	if len(number) >= 2 && number[0] == '.' && '0' <= number[1] && number[1] <= '9' {
		number = number[2:]
		for len(number) > 0 && '0' <= number[0] && number[0] <= '9' {
			number = number[1:]
		}
	}

	if len(number) >= 2 && (number[0] == 'e' || number[0] == 'E') {
		number = number[1:]
		if len(number) == 0 {
			return false
		}
		if number[0] == '+' || number[0] == '-' {
			number = number[1:]
			if len(number) == 0 {
				return false
			}
		}
		for len(number) > 0 && '0' <= number[0] && number[0] <= '9' {
			number = number[1:]
		}
	}

	return len(number) == 0
}
