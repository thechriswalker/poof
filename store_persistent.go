package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"time"

	_ "modernc.org/sqlite"
)

type PersistentStore struct {
	db       *sql.DB
	seed     []byte // persisted in DB
	maxItems uint64 // max items to store
	gc       *time.Ticker
}

func NewPersistentStore(maxItems uint64, dsn string) (*PersistentStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	ps := &PersistentStore{
		db:       db,
		maxItems: maxItems,
	}
	ps.seed, err = initDB(db)
	if err != nil {
		return nil, err
	}
	// one second? probably 10 should be fast enough,
	// minimum expire is 1 minute.
	ps.gc = time.NewTicker(10 * time.Second)
	go func() {
		for {
			// evict first so it happens immediately
			evict(db)
			// wait for a tick.
			<-ps.gc.C
		}
	}()
	return ps, nil
}

var _ IStore = (*PersistentStore)(nil)

const createTables = `
CREATE TABLE IF NOT EXISTS meta (
	seed TEXT, -- base64 encoded seed
	added INTEGER NOT NULL DEFAULT 0, -- the number of items ever added to the store
	expired INTEGER NOT NULL DEFAULT 0, -- the number of items that expired
	burned INTEGER NOT NULL DEFAULT 0 -- the number of items were burned
);

CREATE TABLE IF NOT EXISTS items (
	key BLOB NOT NULL PRIMARY KEY, -- binary data for key, should be indexed
	enc TEXT NOT NULL, -- the encrypted data as given. probably base64 encoded
	hash TEXT NOT NULL, -- the hash of the encryption key.
	expiry INTEGER NOT NULL -- unix timestamp for expiry
);
`

const readMeta = `SELECT seed FROM meta LIMIT 1;`
const createMeta = `INSERT INTO meta (seed) VALUES (?);`

const evictionQuery = `DELETE FROM items WHERE expiry < strftime('%s','now');`

func evict(db *sql.DB) error {
	r, err := db.Exec(evictionQuery)
	if err != nil {
		return err
	}
	var n int64
	n, err = r.RowsAffected()
	if err != nil {
		return err
	}
	if n > 0 {
		_, err = db.Exec(`UPDATE meta SET expired = expired + ?`, n)
	}
	return err
}

func initDB(db *sql.DB) (seed []byte, err error) {
	// try and run the create table sql.
	_, err = db.Exec(createTables)
	if err != nil {
		return nil, err
	}
	// read the meta data.
	var b64seed string
	err = db.QueryRow(readMeta).Scan(&b64seed)
	if err != nil {
		if err != sql.ErrNoRows {
			return nil, err
		}
		// create a random seed and write it back.
		seed := make([]byte, 16)
		rand.Read(seed)
		b64seed = base64.RawURLEncoding.EncodeToString(seed)
		_, err = db.Exec(createMeta, b64seed)
		if err != nil {
			return nil, err
		}
	} else {
		seed, err = base64.RawURLEncoding.DecodeString(b64seed)
		if err != nil {
			return nil, err
		}
	}
	return seed, nil
}

const readMetrics = `
	SELECT
		(SELECT count(*) FROM items) AS size,
		added,
		expired,
		burned
	FROM meta LIMIT 1;
`

func (ps *PersistentStore) Metrics() (size, added, expired, burned uint64) {
	// we ignore the error. we can't handle it.
	// maybe we should log it, but I won't
	_ = ps.db.QueryRow(readMetrics).Scan(&size, &added, &expired, &burned)
	return
}

// Get is actually a DELETE
// we always delete, even if expired.
// we then check the expiry in app.
const getQuery = `DELETE FROM items WHERE key = ? AND hash = ? RETURNING enc, expiry;`

func (ps *PersistentStore) Get(k Key, hash string) (enc string, ok bool) {
	var expiry int64
	err := ps.db.QueryRow(getQuery, k[:], hash).Scan(&enc, &expiry)
	if err != nil {
		// this could be expired or not exists.
		return "", false
	}
	// if it returned and was expired, update the metrics.
	if time.Now().Unix() > expiry {
		// the key was expired (just not evicted yet)
		// we have no recovery from this, so just ignore
		_, _ = ps.db.Exec(`UPDATE meta SET expired = expired+1;`)
		return "", false
	} else {
		// the value is fine, update the "burned" metric
		// we have no recovery from this, so just ignore
		_, _ = ps.db.Exec(`UPDATE meta SET burned = burned+1;`)
		return enc, true
	}
}

// set creates the "key" and stores the value, if space in the DB exists
// there is a race condition here, between check and set, but I don't care
// it's close enough and the limit can be "slightly soft"
func (ps *PersistentStore) Set(enc, hash string, ttl int) (k Key, ok bool) {
	h := sha256.New()
	h.Write(ps.seed)
	h.Write([]byte(enc))
	b := h.Sum(nil)
	copy(k[:], b)
	// we have populated the "key"
	// now we check and insert the value.
	var size uint64
	err := ps.db.QueryRow(`SELECT count(*) FROM items;`).Scan(&size)
	if err != nil {
		return k, false
	}
	if size >= ps.maxItems {
		// nope
		return k, false
	}
	// OK store the data.
	_, err = ps.db.Exec(
		`INSERT INTO items (key, enc, hash, expiry) VALUES (?,?,?,?);`,
		b,
		enc,
		hash,
		time.Now().Unix()+int64(ttl),
	)
	if err != nil {
		return k, false
	}
	// update metrics
	_, _ = ps.db.Exec(`UPDATE meta SET added = added+1`)
	return k, true
}

func (ps *PersistentStore) Close() {
	// stop the scheduled eviction
	ps.gc.Stop()
	// might as well evict before we finish
	_ = evict(ps.db)
	_ = ps.db.Close()
}
