package backend

import (
	"os"
	"path"
)

const (
	// DefaultFileMode contains a secure default file mode
	DefaultFileMode = os.FileMode(0600)
	// DefaultPathMode contains a secure default path mode
	DefaultPathMode = os.FileMode(0700)
)

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
