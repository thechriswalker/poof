package main

import (
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed assets/*
var assets embed.FS

//go:embed templates/*
var templates embed.FS

type Recv struct {
	Enc    *string  `json:"enc"`
	Errors []string `json:"errors"`
}

type Send struct {
	Key    *string  `json:"key"`
	Errors []string `json:"errors"`
}

func main() {
	// look at the flags for the port
	port := flag.Int("port", 5000, "port to run the webserver on")
	maxHTTPBytes := flag.Int64("max-http-size", 50*1024, "Max allowable upload size - affects secrets that can be stored.")
	maxSecretCount := flag.Int("max-secrets", 1048576, "max number of secrets we will store at one time")
	flag.Parse()
	kv := NewStore(*maxSecretCount)
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
			rawkey, ok := kv.Set(enc, hash, ttl)
			if !ok {
				res.Errors = append(res.Errors, "Service at Capacity, please wait for secrets to burn or expire")
				jsonResponse(w, http.StatusServiceUnavailable, res)
				return
			}

			key := base64.RawURLEncoding.EncodeToString(rawkey[:])
			res.Key = &key
			jsonResponse(w, 200, res)
			return
		} else if r.Method == "GET" && r.URL.Path == "/api/stats" {
			s, a, e, b := kv.Metrics()
			jsonResponse(w, 200, map[string]uint64{
				"size":    s,
				"added":   a,
				"expired": e,
				"burned":  b,
			})
			return
		}
		// fallback...
		jsonResponse(w, 404, json.RawMessage(`{"errors":["invalid request"]}`))
	})

	// otherwise we need the client application from the static dir
	// strip the prefix on the embedded data
	mux.Handle("/assets/", http.FileServer(http.FS(assets)))

	// we parse the templates for /index.html /recv/ and /send/
	tpl, err := template.ParseFS(templates, "templates/*.html")
	if err != nil {
		log.Fatal(err)
	}
	// now we need a handler for this.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var name string
		switch r.URL.Path {
		case "/", "/index.html":
			name = "index"
		case "/recv", "/recv/", "/recv/index.html":
			name = "recv"
		case "/send", "/send/", "/send/index.html":
			name = "send"
		default:
			// 404
			http.Error(w, "404: Page not found", 404)
			return
		}

		if err := tpl.ExecuteTemplate(w, name, nil); err != nil {
			// what can we do
			log.Println("Error rendering template:", err)
			http.Error(w, "500: Internal Error", 500)
		}
	})

	// finally wrap everything in a handler that limits the HTTP body size.
	maxUploadWrapper := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, *maxHTTPBytes)
		mux.ServeHTTP(w, r)
	})

	addr := fmt.Sprintf(":%d", *port)
	log.Fatal(http.ListenAndServe(addr, maxUploadWrapper))
}

func jsonResponse(w http.ResponseWriter, code int, msg interface{}) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(msg)
}

// we could use redis for the storage, but we'll just use an in-memory map (with TTL).
type Store struct {
	seed      []byte
	sizeLimit int // how many entries we allow.
	data      map[Key]*Entry
	mtx       *sync.RWMutex

	// metrics
	added   uint64
	expired uint64
	burned  uint64
}

func NewStore(max int) *Store {
	seed := make([]byte, 16)
	rand.Read(seed)
	return &Store{
		seed:      seed,
		sizeLimit: max,
		data:      map[Key]*Entry{},
		mtx:       &sync.RWMutex{},
	}
}

type Key [sha256.Size]byte
type Entry struct {
	Enc, Hash      string // stored as string as we recv as string.
	CancelEviction func()
}

func (kv *Store) Metrics() (size uint64, added uint64, expired uint64, burned uint64) {
	kv.mtx.RLock()
	size = uint64(len(kv.data))
	added, expired, burned = kv.added, kv.expired, kv.burned
	kv.mtx.RUnlock()
	return
}

func (kv *Store) Set(enc, hash string, ttl int) (Key, bool) {
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
	kv.data[key] = &Entry{
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

func (kv *Store) sha(s string) (k Key) {
	h := sha256.New()
	h.Write(kv.seed)
	h.Write([]byte(s))
	b := h.Sum(nil)
	copy(k[:], b)
	return
}

func (kv *Store) delete(k Key, isBurn bool) {
	kv.mtx.Lock()
	delete(kv.data, k)
	if isBurn {
		kv.burned++
	} else {
		kv.expired++
	}
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
	v.CancelEviction()
	kv.delete(k, true)
	// ok, return the data
	return v.Enc, true
}
