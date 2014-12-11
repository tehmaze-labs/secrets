package backend

import "sync"

// Backend interface defines methods for a storage back end
type Backend interface {
	Lock()
	RLock()
	RLocker() sync.Locker
	RUnlock()
	Unlock()

	Prepare(key string) error
	Has(key string) bool
	Get(key string) ([]byte, error)
	Set(key string, data []byte) error
	Delete(key string) error
	Scan(prefix string) <-chan string
}
