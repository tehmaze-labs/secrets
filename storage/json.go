package storage

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// JSONBackend stores arbitrary data structures on disk as JSON formatted files.
type JSONBackend struct {
	sync.RWMutex
	Options       Options
	Compress      bool
	CompressLevel int
}

// NewJSONBackend initialises a new JSON storage backend.
func NewJSONBackend(opt Options) (b *JSONBackend, err error) {
	if opt.TranslatePath == nil {
		opt.TranslatePath = translatePathSimple
	}
	if opt.TranslateFile == nil {
		opt.TranslateFile = jsonTranslateFileSimple
	}

	b = &JSONBackend{
		Options: opt,
	}
	if level, ok := opt.Extra["compress"].(int); ok {
		b.Compress = true
		b.CompressLevel = level
	}

	return b, nil
}

// Marshal translates the object to be stored to a byte slice, it optionally
// compresses the block using gzip if enabled via the "compress" extra option.
func (b *JSONBackend) Marshal(v interface{}) (data []byte, err error) {
	if b.Compress {
		data, err = json.Marshal(v)
		if err != nil {
			return
		}
		var c bytes.Buffer
		z, _ := gzip.NewWriterLevel(&c, b.CompressLevel)
		if _, err = z.Write(data); err != nil {
			return nil, err
		}
		z.Close()
		data = c.Bytes()
	} else {
		data, err = json.MarshalIndent(v, "", "  ")
		if err == nil {
			data = append(data, '\n')
		}
	}
	return
}

// Unmarshal translates the byte slice back to an object.
func (b *JSONBackend) Unmarshal(data []byte, v interface{}) error {
	if b.Compress {
		var b bytes.Buffer
		r, err := gzip.NewReader(bytes.NewBuffer(data))
		if err != nil {
			return err
		}
		io.Copy(&b, r)
		data = b.Bytes()
	}
	return json.Unmarshal(data, v)
}

func jsonTranslateFileSimple(key string) string {
	return key + ".js"
}

func (b *JSONBackend) keyPath(key string) string {
	translated := b.Options.TranslatePath(key)
	return filepath.Join(b.Options.Path, filepath.Join(translated...))
}

func (b *JSONBackend) keyFile(key string) string {
	translated := b.Options.TranslateFile(key)
	return filepath.Join(b.keyPath(key), translated)
}

// Prepare makes sure the path where the key is stored exists prior to saving it.
func (b *JSONBackend) Prepare(key string) (err error) {
	file, err := filepath.Abs(b.keyPath(key))
	if err != nil {
		return err
	}
	if err = os.MkdirAll(file, b.Options.PathMode); err != nil {
		return err
	}
	return nil
}

// Has returns a bool that indicates if the key exists.
func (b *JSONBackend) Has(key string) bool {
	info, err := os.Stat(b.keyFile(key))
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// Get retrieves raw key data from the storage, ready to be unmarshaled.
func (b *JSONBackend) Get(key string) ([]byte, error) {
	return ioutil.ReadFile(b.keyFile(key))
}

// Set writes raw key data to the storage, already marshaled.
func (b *JSONBackend) Set(key string, data []byte) (err error) {
	return ioutil.WriteFile(b.keyFile(key), data, b.Options.FileMode)
}

// Delete removes a key from the storage.
func (b *JSONBackend) Delete(key string) (err error) {
	return os.Remove(b.keyFile(key))
}

// jsonWalker returns a function which satisfies the filepath.WalkFunc interface.
// It sends every non-directory file entry down the channel c.
func jsonWalker(c chan string, prefix string) func(path string, info os.FileInfo, err error) error {
	return func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasPrefix(info.Name(), prefix) && strings.HasSuffix(info.Name(), ".js") {
			var name = info.Name()
			c <- name[:len(name)-3]
		}
		return nil // "pass"
	}
}

// Scan returns a channel that receives keys that match prefix, in no particular order.
func (b *JSONBackend) Scan(prefix string) <-chan string {
	c := make(chan string)
	go func() {
		filepath.Walk(b.keyPath(prefix), jsonWalker(c, prefix))
		close(c)
	}()
	return c
}

// Sanity check
var _ Backend = (*JSONBackend)(nil)
