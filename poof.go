package main

import (
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed assets/*
var assets embed.FS

type Recv struct {
	Enc    *string  `json:"enc"`
	Errors []string `json:"errors"`
}

type Send struct {
	Key    *string  `json:"key"`
	Errors []string `json:"errors"`
}

func main() {
	kv := NewStore()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/api/recv" {
			// handle recv.
			res := &Recv{
				Errors: []string{},
			}
			if err := r.ParseForm(); err != nil {
				res.Errors = append(res.Errors, err.Error())
				jsonResponse(w, 400, res)
				return
			}
			key := r.PostFormValue("key")
			if key == "" {
				res.Errors = append(res.Errors, "`key` was empty")
			}
			hash := r.PostFormValue("hash")
			if hash == "" {
				res.Errors = append(res.Errors, "`hash` was empty")
			}
			// decode key
			k, err := base64.RawURLEncoding.DecodeString(key)
			if err != nil {
				res.Errors = append(res.Errors, "`key` invalid")
			}
			if len(res.Errors) > 0 {
				jsonResponse(w, 400, res)
				return
			}

			var kk Key
			copy(kk[:], k)
			enc, ok := kv.Get(kk, hash)
			if !ok {
				res.Errors = append(res.Errors, "`key` does not exist, is burned or has expired")
				jsonResponse(w, 400, res)
				return
			}

			res.Enc = &enc
			jsonResponse(w, 200, res)
			return
		}
		if r.Method == "POST" && r.URL.Path == "/api/send" {
			// handle send
			res := &Send{
				Errors: []string{},
			}
			if err := r.ParseForm(); err != nil {
				res.Errors = append(res.Errors, err.Error())
				jsonResponse(w, 400, res)
				return
			}
			enc := r.PostFormValue("enc")
			if enc == "" {
				res.Errors = append(res.Errors, "`enc` was empty")
			} else {
				// enc should be in three parts separated by `:`
				fields := strings.Split(enc, ":")
				if len(fields) != 3 {
					res.Errors = append(res.Errors, "`enc` is not correctly formatted")
				}
			}
			hash := r.PostFormValue("hash")
			if hash == "" {
				res.Errors = append(res.Errors, "`hash` was empty")
			} else if len(hash) != 43 {
				// hash should be a sha256 hash, in base64url
				// we will just check the length.
				res.Errors = append(res.Errors, "`hash` does not look like a base64url encoded SHA256 hash (without padding)")
			}

			sttl := r.PostFormValue("ttl")
			var ttl int
			if sttl == "" {
				res.Errors = append(res.Errors, "`ttl` was empty")
			} else {
				var err error
				ttl, err = strconv.Atoi(sttl)
				if err != nil {
					res.Errors = append(res.Errors, "`ttl` was not an integer")
				} else if ttl < 60 {
					res.Errors = append(res.Errors, "`ttl` was less than 1 minute")
				} else if ttl > 86400*7 {
					res.Errors = append(res.Errors, "`ttl` was greater than 7 days")
				}
			}

			if len(res.Errors) > 0 {
				jsonResponse(w, 400, res)
				return
			}

			// OK store the data!
			rawkey := kv.Set(enc, hash, ttl)

			key := base64.RawURLEncoding.EncodeToString(rawkey[:])
			res.Key = &key
			jsonResponse(w, 200, res)
			return
		}
		// fallback...
		jsonResponse(w, 404, json.RawMessage(`{"errors":["invalid request"]}`))
	})
	// otherwise we need the client application from the static dir
	// strip the prefix on the embedded data
	dir, err := fs.Sub(assets, "assets")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("/", http.FileServer(http.FS(dir)))

	log.Fatal(http.ListenAndServe("0:5000", mux))
}

func jsonResponse(w http.ResponseWriter, code int, msg interface{}) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(msg)
}

// we could use redis for the storage, but we'll just use an in-memory map (with TTL).
type Store struct {
	seed []byte
	data map[Key]*Entry
	mtx  *sync.RWMutex
}

func NewStore() *Store {
	seed := make([]byte, 16)
	rand.Read(seed)
	return &Store{
		seed: seed,
		data: map[Key]*Entry{},
		mtx:  &sync.RWMutex{},
	}
}

type Key [sha256.Size]byte
type Entry struct {
	Enc, Hash      string // stored as string as we recv as string.
	CancelEviction func()
}

func (kv *Store) Set(enc, hash string, ttl int) Key {
	// the key is the hash of the encrypted enc, to prevent collisions.
	key := kv.sha(enc)
	kv.mtx.Lock()
	timer := time.AfterFunc(time.Duration(ttl)*time.Second, func() {
		log.Printf("Expiring Key %02x", key)
		kv.delete(key)
	})
	kv.data[key] = &Entry{
		Enc:  enc,
		Hash: hash,
		CancelEviction: func() {
			timer.Stop()
		},
	}
	log.Printf("Adding Key %02x", key)
	kv.mtx.Unlock()

	return key
}

func (kv *Store) sha(s string) (k Key) {
	h := sha256.New()
	h.Write(kv.seed)
	h.Write([]byte(s))
	b := h.Sum(nil)
	copy(k[:], b)
	return
}

func (kv *Store) delete(k Key) {
	kv.mtx.Lock()
	delete(kv.data, k)
	kv.mtx.Unlock()
}

func (kv *Store) Get(k Key, hash string) (enc string, ok bool) {
	kv.mtx.RLock()
	v, ok := kv.data[k]
	if !ok || v.Hash != hash {
		kv.mtx.RUnlock()
		return enc, false
	}
	kv.mtx.RUnlock()
	// we got a hit. We need to remove the key.
	log.Printf("Burning Key %02x", k)
	v.CancelEviction()
	kv.delete(k)
	// ok, return the data
	return v.Enc, true
}
