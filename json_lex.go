package masker

func skipJSONSpace(data []byte, index int) int {
	for index < len(data) {
		switch data[index] {
		case ' ', '\t', '\r', '\n':
			index++
		default:
			return index
		}
	}
	return index
}

func scanJSONString(data []byte, start int) int {
	for index := start + 1; index < len(data); index++ {
		switch data[index] {
		case '\\':
			index++
		case '"':
			return index + 1
		}
	}
	return len(data)
}

func scanJSONPrimitive(data []byte, start int) int {
	for index := start; index < len(data); index++ {
		switch data[index] {
		case ' ', '\t', '\r', '\n', ',', ']', '}':
			return index
		}
	}
	return len(data)
}
