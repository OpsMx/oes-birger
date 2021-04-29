package tunnel

func (t *HttpRequest) GetHeaderValue(name string) string {
	for _, header := range t.Headers {
		if header.Name == name {
			return header.Values[0]
		}
	}
	return ""
}
