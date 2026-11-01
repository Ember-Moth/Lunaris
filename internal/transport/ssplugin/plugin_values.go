// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
package plugin

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
)

type pluginValues struct {
	plugin Name
	values map[string]any
}

func newPluginValues(plugin Name, values map[string]any) *pluginValues {
	return &pluginValues{plugin: plugin, values: values}
}

func (values *pluginValues) take(field string, aliases ...string) (any, bool, error) {
	keys := append([]string{field}, aliases...)
	var result any
	found := false
	for _, key := range keys {
		value, exists := values.values[key]
		if !exists {
			continue
		}
		delete(values.values, key)
		if found {
			return nil, false, values.invalid(field)
		}
		result, found = value, true
	}
	return result, found, nil
}

func (values *pluginValues) string(field, fallback string, required bool, aliases ...string) (string, error) {
	value, found, err := values.take(field, aliases...)
	if err != nil {
		return "", err
	}
	if !found {
		if required {
			return "", values.invalid(field)
		}
		return fallback, nil
	}
	text, ok := value.(string)
	if !ok || required && strings.TrimSpace(text) == "" {
		return "", values.invalid(field)
	}
	return text, nil
}

func (values *pluginValues) boolean(field string, fallback bool, aliases ...string) (bool, error) {
	value, found, err := values.take(field, aliases...)
	if err != nil || !found {
		return fallback, err
	}
	switch typed := value.(type) {
	case bool:
		return typed, nil
	case string:
		parsed, parseErr := strconv.ParseBool(typed)
		if parseErr == nil {
			return parsed, nil
		}
	}
	return false, values.invalid(field)
}

func (values *pluginValues) integer(field string, fallback int, aliases ...string) (int, error) {
	value, found, err := values.take(field, aliases...)
	if err != nil || !found {
		return fallback, err
	}
	var number int64
	switch typed := value.(type) {
	case json.Number:
		number, err = typed.Int64()
	case int:
		return typed, nil
	case int64:
		number = typed
	case float64:
		number = int64(typed)
		if float64(number) != typed {
			err = ErrInvalidOption
		}
	case string:
		number, err = strconv.ParseInt(typed, 10, 32)
	default:
		err = ErrInvalidOption
	}
	if err != nil || int64(int(number)) != number {
		return 0, values.invalid(field)
	}
	return int(number), nil
}

func (values *pluginValues) stringMap(field string) (map[string]string, error) {
	value, found, err := values.take(field)
	if err != nil || !found {
		return nil, err
	}
	if typed, ok := value.(map[string]string); ok {
		return typed, nil
	}
	typed, ok := value.(map[string]any)
	if !ok {
		return nil, values.invalid(field)
	}
	result := make(map[string]string, len(typed))
	for key, item := range typed {
		text, ok := item.(string)
		if !ok {
			return nil, values.invalid(field)
		}
		result[key] = text
	}
	return result, nil
}

func (values *pluginValues) finish() error {
	if len(values.values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values.values))
	for key := range values.values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return values.invalid(keys[0])
}

func (values *pluginValues) invalid(field string) error {
	return &Error{Plugin: values.plugin, Field: field, Cause: ErrInvalidOption}
}
