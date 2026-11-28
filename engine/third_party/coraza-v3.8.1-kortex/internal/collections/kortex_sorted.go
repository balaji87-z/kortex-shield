// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// kortex-shield patch (step 23): not part of coraza v3.8.1.

package collections

import "sort"

// sortedKeys returns the keys of a collection's map in ascending order, so
// that FindAll and FindRegex hand rules the same variables in the same order
// on every call instead of Go's random map order.
func sortedKeys(m map[string][]keyValue) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
