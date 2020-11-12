/*
Copyright © 2019 Doppler <support@doppler.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package models

import (
	"bytes"
	"fmt"
	"regexp"
)

// VarExpressions comment
var VarExpressions = map[string]SubstituteText{
	"dollar":            subFactory(`\$%s\b`),
	"dollar-curly":      subFactory(`\$\{%s\}`),
	"handlebars":        subFactory(`\{\{%s\}\}`),
	"dollar-handlebars": subFactory(`\$\{\{%s\}\}`),
}

// SubstituteText somrething
type SubstituteText func(text []byte, subs map[string]ComputedSecret) []byte

// subFactory something
func subFactory(expression string) SubstituteText {
	var secretKeyGroup string = "([A-Z_][A-Z0-9_]*)"
	return func(text []byte, subs map[string]ComputedSecret) []byte {
		exp := regexp.MustCompile(fmt.Sprintf(expression, secretKeyGroup))

		matches := exp.FindAllSubmatch(text, -1)
		for _, match := range matches {
			keyStr := string(match[1])

			if subs[keyStr].ComputedValue != "" {
				text = bytes.Replace(text, match[0], []byte(subs[keyStr].ComputedValue), 1)
			}
		}
		return text
	}
}
