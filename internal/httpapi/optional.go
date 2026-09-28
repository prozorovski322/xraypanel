package httpapi

import "encoding/json"

// optional distinguishes three states of a JSON field: absent, explicitly null, and
// carrying a value.
//
// A double pointer does not do this. For a `**string` field, encoding/json decodes
// `"field": null` by setting the outer pointer to nil, which is indistinguishable from the
// key being absent. The distinction matters wherever null is a meaningful value rather than
// a missing one: clearing a user's expiry means "never expires", clearing a host's port
// means "inherit the inbound's", and clearing an inbound's flow means "no flow". With a
// double pointer all three are silently unreachable over the API.
//
// A type implementing json.Unmarshaler is called only when the key is present, including
// when its value is null, which is exactly the signal needed.
type optional[T any] struct {
	set   bool
	value *T
}

// UnmarshalJSON records that the field was present and captures its value.
func (o *optional[T]) UnmarshalJSON(data []byte) error {
	o.set = true

	if string(data) == "null" {
		o.value = nil
		return nil
	}

	var value T
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	o.value = &value
	return nil
}

// MarshalJSON is provided so a struct carrying this type can round-trip in tests.
func (o optional[T]) MarshalJSON() ([]byte, error) {
	if o.value == nil {
		return []byte("null"), nil
	}
	return json.Marshal(*o.value)
}

// Present reports whether the key appeared in the request at all.
func (o optional[T]) Present() bool { return o.set }

// Value returns the decoded value, or nil when the field was explicitly null.
func (o optional[T]) Value() *T { return o.value }

// ValueOr returns the value, or a fallback when the field was absent or null.
func (o optional[T]) ValueOr(fallback T) T {
	if o.value == nil {
		return fallback
	}
	return *o.value
}
