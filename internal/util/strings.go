package util

// UniqueStrings returns a deduplicated copy of the slice preserving insertion order.
// Returns nil for empty or nil input.
func UniqueStrings(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(s))
	result := make([]string, 0, len(s))
	for _, v := range s {
		if _, exists := seen[v]; !exists {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}
	return result
}
