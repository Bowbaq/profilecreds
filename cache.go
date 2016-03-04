package profilecreds

import (
	"encoding/json"
	"os"
	"path"
	"sync"
)

// Cache is the interface used by AssumeRoleProfileProvider to store temporary credentials
type Cache interface {
	// Set adds a new value to the cache, overwritting any pre-existing value
	Set(key, value string)

	// Get a value from the cache. found is false if the value wasn't present
	Get(key string) (value string, found bool)
}

// FileCache is a simple implementation of Cache backed by a file
type FileCache struct {
	m    sync.Mutex
	data map[string]string

	filename string
}

// NewFileCache returns a new instance of FileCache. If filename is "", a temporary location is chosen.
func NewFileCache(filename string) *FileCache {
	if filename == "" {
		filename = path.Join(os.TempDir(), "credentials")
	}

	return &FileCache{
		filename: filename,
	}
}

// Set adds a new value to the cache, overwritting any pre-existing value
func (f *FileCache) Set(key, value string) {
	if f.data == nil {
		f.readConf()
	}

	f.m.Lock()
	f.data[key] = value
	f.m.Unlock()

	f.writeConf()
}

// Get a value from the cache. found is false if the value wasn't present
func (f *FileCache) Get(key string) (string, bool) {
	if f.data == nil {
		f.readConf()
	}

	f.m.Lock()
	value, found := f.data[key]
	f.m.Unlock()

	return value, found
}

func (f *FileCache) readConf() {
	f.m.Lock()
	defer f.m.Unlock()

	f.data = make(map[string]string)

	file, err := os.Open(f.filename)
	if err != nil {
		return
	}

	json.NewDecoder(file).Decode(&f.data)
}

func (f *FileCache) writeConf() {
	f.m.Lock()
	defer f.m.Unlock()

	file, err := os.OpenFile(f.filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return
	}

	json.NewEncoder(file).Encode(f.data)
}
