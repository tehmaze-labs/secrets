package backend

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// FileBackend stores arbitrary data structures on disk as File formatted files.
type FileBackend struct {
	sync.RWMutex
	Options       Options
	Compress      bool
	CompressLevel int
	Extension     string
	TranslateFile TranslateFileFunc
	TranslatePath TranslatePathFunc
}

// NewFileBackend initialises a new File storage backend.
func NewFileBackend(opt Options) (b *FileBackend, err error) {
	b = &FileBackend{
		Options:       opt,
		TranslateFile: opt.TranslateFile,
		TranslatePath: opt.TranslatePath,
	}
	if b.TranslatePath == nil {
		b.TranslatePath = translatePathSimple
	}
	if b.TranslateFile == nil {
		b.TranslateFile = b.FileTranslateSimple
	}

	if extension, ok := opt.Extra["extension"].(string); ok {
		b.Extension = extension
	} else {
		b.Extension = "storage"
	}
	if level, ok := opt.Extra["compress"].(int); ok {
		b.Compress = true
		b.CompressLevel = level
	}

	return b, nil
}

// FileTranslateSimple converts a key to key plus file extension.
func (b *FileBackend) FileTranslateSimple(key string) string {
	return key + "." + b.Extension
}

func (b *FileBackend) keyPath(key string) string {
	translated := b.TranslatePath(key)
	return filepath.Join(b.Options.Path, filepath.Join(translated...))
}

func (b *FileBackend) keyFile(key string) string {
	translated := b.TranslateFile(key)
	return filepath.Join(b.keyPath(key), translated)
}

// Prepare makes sure the path where the key is stored exists prior to saving it.
func (b *FileBackend) Prepare(key string) (err error) {
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
func (b *FileBackend) Has(key string) bool {
	info, err := os.Stat(b.keyFile(key))
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// Get retrieves raw key data from the storage, ready to be unmarshaled.
func (b *FileBackend) Get(key string) (data []byte, err error) {
	data, err = ioutil.ReadFile(b.keyFile(key))
	if err != nil && b.Compress {
		var b bytes.Buffer
		r, err := gzip.NewReader(bytes.NewBuffer(data))
		if err != nil {
			return data, err
		}
		io.Copy(&b, r)
		data = b.Bytes()
	}
	return
}

// Set writes raw key data to the storage, already marshaled.
func (b *FileBackend) Set(key string, data []byte) (err error) {
	if b.Compress {
		var c bytes.Buffer
		z, _ := gzip.NewWriterLevel(&c, b.CompressLevel)
		if _, err = z.Write(data); err != nil {
			return err
		}
		z.Close()
		data = c.Bytes()
	}
	return ioutil.WriteFile(b.keyFile(key), data, b.Options.FileMode)
}

// Delete removes a key from the storage.
func (b *FileBackend) Delete(key string) (err error) {
	return os.Remove(b.keyFile(key))
}

// FileWalker returns a function which satisfies the filepath.WalkFunc interface.
// It sends every non-directory file entry down the channel c.
func FileWalker(c chan string, prefix string) func(path string, info os.FileInfo, err error) error {
	return func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasPrefix(info.Name(), prefix) && strings.HasSuffix(info.Name(), ".js") {
			var name = info.Name()
			c <- name[:len(name)-3]
		}
		return nil // "pass"
	}
}

// Scan returns a channel that receives keys that match prefix, in no particular order.
func (b *FileBackend) Scan(prefix string) <-chan string {
	c := make(chan string)
	go func() {
		filepath.Walk(b.keyPath(prefix), FileWalker(c, prefix))
		close(c)
	}()
	return c
}

// Sanity check
var _ Backend = (*FileBackend)(nil)
