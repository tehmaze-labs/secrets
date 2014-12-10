package storage

import (
	"errors"
	"os"
	"path"
	"strings"
	"sync"
)

const (
	// DefaultFileMode contains a secure default file mode
	DefaultFileMode = os.FileMode(0600)
	// DefaultPathMode contains a secure default path mode
	DefaultPathMode = os.FileMode(0700)
)

// Backend interface defines methods for a storage back end
type Backend interface {
	Lock()
	RLock()
	RLocker() sync.Locker
	RUnlock()
	Unlock()

	Prepare(key string) error
	Marshal(v interface{}) ([]byte, error)
	Unmarshal(data []byte, v interface{}) error

	Has(key string) bool
	Get(key string) ([]byte, error)
	Set(key string, data []byte) error
	Delete(key string) error
	Scan(prefix string) <-chan string
}

// Storage ...
type Storage struct {
	Backend Backend
}

// Options ...
type Options struct {
	Path          string
	TranslatePath TranslatePathFunc
	TranslateFile TranslateFileFunc
	FileMode      os.FileMode
	PathMode      os.FileMode
	Extra         map[string]interface{}
}

// NewOptions creates a new Options structure for the given path, with defaults.
func NewOptions(dir string) Options {
	return Options{
		Path:     path.Clean(dir),
		FileMode: DefaultFileMode,
		PathMode: DefaultPathMode,
		Extra:    map[string]interface{}{},
	}
}

// TranslatePathFunc translates a key to a directory that contains the key file.
type TranslatePathFunc func(key string) []string

// TranslateFileFunc translates a key to a file path to the key file without its path.
type TranslateFileFunc func(key string) string

// translatePathSimple uses a single directory for all keys
func translatePathSimple(key string) []string { return []string{} }

// translateFileSimple uses the key as file name
func translateFileSimple(key string) string { return key }

// New initializes a new Storage backend.
func New(b Backend) *Storage {
	s := &Storage{
		Backend: b,
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
	if err = s.Backend.Unmarshal(data, v); err != nil {
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
	data, err := s.Backend.Marshal(v)
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
