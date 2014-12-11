package storage

import (
	"encoding/json"

	"github.com/tehmaze-labs/secrets/storage/backend"
)

// NewJSON (un)marshals interfaces to and from JSON.
func NewJSON(b backend.Backend) *Storage {
	if fb, ok := b.(*backend.FileBackend); ok {
		fb.Extension = "js"
	}
	return &Storage{
		Backend:   b,
		Marshal:   marshalJSON,
		Unmarshal: unmarshalJSON,
	}
}

// Marshal translates the object to be stored to a byte slice, it optionally
// compresses the block using gzip if enabled via the "compress" extra option.
func marshalJSON(v interface{}) (data []byte, err error) {
	data, err = json.MarshalIndent(v, "", "  ")
	if err == nil {
		data = append(data, '\n')
	}
	return
}

// Unmarshal translates the byte slice back to an object.
func unmarshalJSON(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
