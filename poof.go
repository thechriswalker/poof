package main

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
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
	persist := flag.String("persist", "", "set to a filename to persist data between restarts")
	maxHTTPBytes := flag.Int64("max-http-size", 50*1024, "Max allowable upload size - affects secrets that can be stored.")
	maxSecretCount := flag.Int("max-secrets", 1048576, "max number of secrets we will store at one time")
	flag.Parse()
	var kv IStore
	if *persist == "" {
		kv = NewMemoryStore(*maxSecretCount)
	} else {
		var err error
		kv, err = NewPersistentStore(uint64(*maxSecretCount), *persist)
		if err != nil {
			log.Fatalln(err)
		}
	}
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
		case "/faq", "/faq/", "/faq/index.html":
			name = "faq"
		case "/recv", "/recv/", "/recv/index.html":
			name = "recv"
		case "/", "/index.html", "/send", "/send/", "/send/index.html":
			name = "send"
		case "/privacy", "/privacy/", "/privacy/index.html":
			name = "privacy"
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

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", *port),
		Handler: maxUploadWrapper,
	}
	ec := make(chan error)
	go func() {
		ec <- server.ListenAndServe()
	}()
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)
	<-c
	server.Shutdown(context.Background())
	if err := <-ec; err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func jsonResponse(w http.ResponseWriter, code int, msg interface{}) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(msg)
}

type Key [sha256.Size]byte

// IStore interface has no way to manually delete a key
// instead get implicitly removes and set has a ttl.
type IStore interface {
	Metrics() (size uint64, added uint64, expired uint64, burned uint64)
	Set(enc, hash string, ttl int) (Key, bool)
	Get(k Key, hash string) (enc string, ok bool)
	Close()
}
