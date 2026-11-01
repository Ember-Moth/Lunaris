// Derived from XTLS/Xray-core infra/conf/common.go at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.

package xhttp

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
)

// Range is an inclusive integer range written as "from-to" or a single value.
type Range struct {
	From int32
	To   int32
}

// UnmarshalJSON accepts a "from-to" string, a single number or a {from, to}
// object.
func (value *Range) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		from, to, err := parseRange(text)
		if err != nil {
			return err
		}
		if from < math.MinInt32 || to > math.MaxInt32 {
			return errors.New("xhttp: range exceeds int32")
		}
		value.From, value.To = int32(from), int32(to)
		return nil
	}
	var number int32
	if err := json.Unmarshal(data, &number); err == nil {
		value.From, value.To = number, number
		return nil
	}
	var object struct {
		From int32 `json:"from"`
		To   int32 `json:"to"`
	}
	if err := json.Unmarshal(data, &object); err == nil {
		value.From, value.To = object.From, object.To
		value.order()
		return nil
	}
	return errors.New("xhttp: range must be an integer, range string, or object")
}

func parseRange(text string) (int, int, error) {
	if text == "" {
		return 0, 0, nil
	}
	if value, err := strconv.Atoi(text); err == nil {
		return value, value, nil
	}
	separator := strings.IndexByte(text[1:], '-')
	if separator < 0 {
		return 0, 0, fmt.Errorf("xhttp: invalid range %q", text)
	}
	separator++
	left, leftErr := strconv.Atoi(text[:separator])
	right, rightErr := strconv.Atoi(text[separator+1:])
	if leftErr != nil || rightErr != nil {
		return 0, 0, fmt.Errorf("xhttp: invalid range %q", text)
	}
	if left > right {
		left, right = right, left
	}
	return left, right, nil
}

func (value *Range) order() {
	if value.From > value.To {
		value.From, value.To = value.To, value.From
	}
}

func (value Range) random() int {
	value.order()
	if value.From == value.To {
		return int(value.From)
	}
	span := int64(value.To) - int64(value.From) + 1
	if span <= 0 {
		return int(value.From)
	}
	n, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return int(value.From)
	}
	return int(int64(value.From) + n.Int64())
}

func (value Range) zero() bool { return value.From == 0 && value.To == 0 }
