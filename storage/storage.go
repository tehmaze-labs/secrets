package storage

import (
	"errors"
	"os"
	"strings"

	"github.com/tehmaze-labs/secrets/storage/backend"
)

// Storage ...
type Storage struct {
	Backend   backend.Backend
	Marshal   MarshalFunc
	Unmarshal UnmarshalFunc
}

/*
Marshal(v interface{}) ([]byte, error)
Unmarshal(data []byte, v interface{}) error
*/

// MarshalFunc converts an interface to bytes that can be stored.
type MarshalFunc func(v interface{}) ([]byte, error)

// UnmarshalFunc coverts stored bytes to an interface.
type UnmarshalFunc func(data []byte, v interface{}) error

// New initializes a new Storage backend.
func New(b backend.Backend, m MarshalFunc, u UnmarshalFunc) *Storage {
	s := &Storage{
		Backend:   b,
		Marshal:   m,
		Unmarshal: u,
	}
	return s
}

// Has checks if the given key has been defined.
func (s *Storage) Has(key string) bool {
	return s.Backend.Has(key)
}

// Get returns the value for a key.
func (s *Storage) Get(key string, v interface{}) (err error) {
	s.Backend.RLock()
	defer s.Backend.RUnlock()
	data, err := s.Backend.Get(key)
	if err != nil {
		return err
	}
	if err = s.Unmarshal(data, v); err != nil {
		return err
	}
	return nil
}

// Set stores the value for a key.
func (s *Storage) Set(key string, v interface{}) (err error) {
	s.Backend.Lock()
	defer s.Backend.Unlock()
	if err = s.Backend.Prepare(key); err != nil {
		return errors.New("prepare failed: " + err.Error())
	}
	data, err := s.Marshal(v)
	if err != nil {
		return errors.New("marshal failed: " + err.Error())
	}
	return s.Backend.Set(key, data)
}

// Delete removes a key from the storage.
func (s *Storage) Delete(key string) error {
	return s.Backend.Delete(key)
}

// Scan returns all keys found with prefix, in no particular order.
func (s *Storage) Scan(prefix string) <-chan string {
	return s.Backend.Scan(prefix)
}

// walker returns a function which satisfies the filepath.WalkFunc interface.
// It sends every non-directory file entry down the channel c.
func walker(c chan string, prefix string) func(path string, info os.FileInfo, err error) error {
	return func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasPrefix(info.Name(), prefix) {
			c <- info.Name()
		}
		return nil // "pass"
	}
}
