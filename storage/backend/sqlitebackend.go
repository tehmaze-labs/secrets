package backend

import (
	"database/sql"
	"errors"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

var sqliteSchema = `
CREATE TABLE IF NOT EXISTS storage (
    key  TEXT NOT NULL PRIMARY KEY,
    val  BLOB
);
`

type SqliteBackend struct {
	sync.RWMutex
	Options Options
	DB      *sql.DB
}

func NewSqliteBackend(opt Options) (b *SqliteBackend, err error) {
	db, err := sql.Open("sqlite3", opt.Path+".sqlite3")
	if err != nil {
		return nil, err
	}
	if _, err = db.Exec(sqliteSchema); err != nil {
		db.Close()
		return nil, err
	}
	b = &SqliteBackend{
		Options: opt,
		DB:      db,
	}
	return b, nil
}

// exec executes a simple SQL query without return
func (b *SqliteBackend) exec(query string, v ...interface{}) (err error) {
	tx, err := b.DB.Begin()
	if err != nil {
		return err
	}
	stm, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stm.Close()
	if _, err = stm.Exec(v...); err != nil {
		return err
	}
	tx.Commit()
	return nil
}

// Prepare makes sure the path where the key is stored exists prior to saving it.
func (b *SqliteBackend) Prepare(key string) (err error) {
	return // noop
}

// Delete removes a row from the table.
func (b *SqliteBackend) Delete(key string) (err error) {
	return b.exec("delete from storage where key = ?", key)
}

// Has returns a bool that indicates if the key exists.
func (b *SqliteBackend) Has(key string) bool {
	rows, err := b.DB.Query("select 1 from storage where key = ?", key)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		return true
	}
	return false
}

// Get retrieves raw key data from the storage, ready to be unmarshaled.
func (b *SqliteBackend) Get(key string) (data []byte, err error) {
	rows, err := b.DB.Query("select val from storage where key = ?", key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		rows.Scan(&data)
		return
	}
	return nil, errors.New(`not found`)
}

// Set writes raw key data to the storage, already marshaled.
func (b *SqliteBackend) Set(key string, data []byte) (err error) {
	return b.exec(`insert into storage (key, val) values (?, ?)`, key, data)
}

// Scan returns a channel that receives keys that match prefix, in no particular order.
func (b *SqliteBackend) Scan(prefix string) <-chan string {
	c := make(chan string)
	go func(db *sql.DB) {
		rows, err := db.Query(`select key from storage where key like ? || "%"`, prefix)
		if err != nil {
			close(c)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var key string
			rows.Scan(&key)
			c <- key
		}
		close(c)
	}(b.DB)
	return c
}

// Sanity check
var _ Backend = (*SqliteBackend)(nil)
