package main

import (
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"time"
)

// Memory Store is not persistent
type MemoryStore struct {
	seed      []byte
	sizeLimit int // how many entries we allow.
	data      map[Key]*memEntry
	mtx       *sync.RWMutex

	// metrics
	added   uint64
	expired uint64
	burned  uint64
}

var _ IStore = (*MemoryStore)(nil)

func NewMemoryStore(max int) *MemoryStore {
	seed := make([]byte, 16)
	rand.Read(seed)
	return &MemoryStore{
		seed:      seed,
		sizeLimit: max,
		data:      map[Key]*memEntry{},
		mtx:       &sync.RWMutex{},
	}
}

type memEntry struct {
	Enc, Hash      string // stored as string as we recv as string.
	CancelEviction func()
}

func (kv *MemoryStore) Close() {
	//no-op
}

func (kv *MemoryStore) Metrics() (size uint64, added uint64, expired uint64, burned uint64) {
	kv.mtx.RLock()
	size = uint64(len(kv.data))
	added, expired, burned = kv.added, kv.expired, kv.burned
	kv.mtx.RUnlock()
	return
}

func (kv *MemoryStore) Set(enc, hash string, ttl int) (Key, bool) {
	// the key is the hash of the encrypted enc, to prevent collisions.
	key := kv.sha(enc)
	kv.mtx.Lock()
	if kv.sizeLimit > 0 && kv.sizeLimit <= len(kv.data) {
		// nope.
		kv.mtx.Unlock()
		return key, false
	}
	timer := time.AfterFunc(time.Duration(ttl)*time.Second, func() {
		kv.delete(key, false)
	})
	kv.data[key] = &memEntry{
		Enc:  enc,
		Hash: hash,
		CancelEviction: func() {
			timer.Stop()
		},
	}
	kv.added++
	kv.mtx.Unlock()
	return key, true
}

func (kv *MemoryStore) sha(s string) (k Key) {
	h := sha256.New()
	h.Write(kv.seed)
	h.Write([]byte(s))
	b := h.Sum(nil)
	copy(k[:], b)
	return
}

func (kv *MemoryStore) delete(k Key, isBurn bool) {
	kv.mtx.Lock()
	delete(kv.data, k)
	if isBurn {
		kv.burned++
	} else {
		kv.expired++
	}
	kv.mtx.Unlock()
}

func (kv *MemoryStore) Get(k Key, hash string) (enc string, ok bool) {
	kv.mtx.RLock()
	v, ok := kv.data[k]
	if !ok || v.Hash != hash {
		kv.mtx.RUnlock()
		return enc, false
	}
	kv.mtx.RUnlock()
	// we got a hit. We need to remove the key.
	v.CancelEviction()
	kv.delete(k, true)
	// ok, return the data
	return v.Enc, true
}
