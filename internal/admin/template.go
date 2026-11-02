// SPDX-License-Identifier: GPL-3.0-only
package admin

import (
	"encoding/json"
	"errors"
	"io"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Convert bounded YAML nodes directly, avoiding alias expansion and quadratic
// duplicate-key handling on attacker-controlled mappings.
func templateJSON(content string) ([]byte, error) {
	decoder := yaml.NewDecoder(strings.NewReader(content))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, errors.New("invalid YAML")
	}
	if err := decoder.Decode(new(yaml.Node)); err != io.EOF {
		return nil, errors.New("multiple YAML documents")
	}
	count := 0
	var convert func(*yaml.Node, int) (any, error)
	convert = func(node *yaml.Node, depth int) (any, error) {
		count++
		if count > 50000 || depth > 64 || node.Anchor != "" || node.Kind == yaml.AliasNode {
			return nil, errors.New("YAML complexity exceeds limit")
		}
		switch node.Kind {
		case yaml.DocumentNode:
			if len(node.Content) != 1 {
				return nil, errors.New("invalid document")
			}
			return convert(node.Content[0], depth+1)
		case yaml.MappingNode:
			if len(node.Content) > 8192 {
				return nil, errors.New("mapping too large")
			}
			value := map[string]any{}
			for i := 0; i < len(node.Content); i += 2 {
				key := node.Content[i]
				if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Anchor != "" {
					return nil, errors.New("mapping keys must be strings")
				}
				if _, exists := value[key.Value]; exists {
					return nil, errors.New("duplicate mapping key")
				}
				item, err := convert(node.Content[i+1], depth+1)
				if err != nil {
					return nil, err
				}
				value[key.Value] = item
			}
			return value, nil
		case yaml.SequenceNode:
			if len(node.Content) > 4096 {
				return nil, errors.New("sequence too large")
			}
			value := make([]any, 0, len(node.Content))
			for _, child := range node.Content {
				item, err := convert(child, depth+1)
				if err != nil {
					return nil, err
				}
				value = append(value, item)
			}
			return value, nil
		case yaml.ScalarNode:
			switch node.Tag {
			case "!!str", "!!int", "!!bool", "!!float", "!!null":
			default:
				return nil, errors.New("unsupported YAML tag")
			}
			var value any
			if err := node.Decode(&value); err != nil {
				return nil, errors.New("invalid scalar")
			}
			return value, nil
		default:
			return nil, errors.New("unsupported YAML node")
		}
	}
	value, err := convert(&document, 0)
	if err != nil {
		return nil, err
	}
	return json.Marshal(value)
}
