package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Message struct {
	Id     string `json:"id"`
	Path   string `json:"path"`
	Data   string `json:"data"`
	Depth  int    `json:"depth"`
	PubKey string `json:"pubKey"`
	Sig    string `json:"sig"`
}

func writeData(w http.ResponseWriter, jData []byte) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	w.Write(jData)
}

func main() {
	db, err := sql.Open("sqlite3", "./database.sqlite")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	sqlStmt := `
	CREATE TABLE IF NOT EXISTS message (id TEXT, data TEXT, depth INT, pubkey TEXT, sig TEXT);
	CREATE INDEX IF NOT EXISTS message_id_idx ON message(id);
	`
	_, err = db.Exec(sqlStmt)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
		queryValues := r.URL.Query()
		// TODO Get all messages with this prefix
		thread := queryValues.Get("thread")
		// TODO Get all depth 1 messages with this prefix
		board := queryValues.Get("board")
		log.Println(thread, board)
		response := make([]Message, 0)
		rows, err := db.Query("select id, data, depth, pubkey, sig from message where depth = 1 and id LIKE ? order by id asc", "/%")
		defer rows.Close()
		for rows.Next() {
			var id string
			var data string
			var depth int
			var pubkey sql.NullString
			var sig sql.NullString
			err = rows.Scan(&id, &data, &depth, &pubkey, &sig)
			if err != nil {
				log.Fatal(err)
			}
			// Create a new Message, add to array
			msg := Message{Id: id, Data: data, Depth: depth, PubKey: pubkey.String, Sig: sig.String}
			response = append(response, msg)
			log.Println(msg)
		}
		err = rows.Err()
		if err != nil {
			log.Fatal(err)
		}
		jData, err := json.Marshal(response)
		if err != nil {
			log.Fatal(err)
		}
		writeData(w, jData)
	})

	http.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			decoder := json.NewDecoder(r.Body)
			var msg Message
			err := decoder.Decode(&msg)
			if err != nil {
				panic(err)
			}
			defer r.Body.Close()
			log.Println(msg)
			stmt, err := db.Prepare("INSERT INTO message VALUES (?, ?, ?, ?, ?)")
			if err != nil {
				log.Fatal(err)
			}
			id := msg.Path + "/" + time.Now().UTC().Format(time.RFC3339Nano)
			_, err = stmt.Exec(id, msg.Data, len(strings.Split(id, "/"))-1, msg.PubKey, msg.Sig)
			if err != nil {
				log.Fatal(err)
			}
			// TODO enforce that the path begins with "/"
			// TODO Send the posted message back to the client
			writeData(w, []byte{})
			// TODO forward these messages to our peers
		}
	})
	log.Fatal(http.ListenAndServe(":"+os.Getenv("PORT"), nil))

}
