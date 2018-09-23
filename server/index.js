const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./database.sqlite');
const http = require('http');
const dht = require('./dht');

db.serialize(function() {
    db.run("CREATE TABLE IF NOT EXISTS message (id TEXT, depth INT, data TEXT, pubkey TEXT, sig TEXT)");
    db.run("CREATE INDEX IF NOT EXISTS message_id_idx ON message(id)");
});

const server = http.createServer((req, res) => {
    console.log(req.url);
    if (req.url.startsWith('/messages')) {
        /*
        if (req.query.board) {
            
        }
        if (req.query.thread) {
            
        }
        */
        // TODO API should support queries for top level messages (boards), all messages within a topic (threads)
        // TODO add endpoints to get all messages in a board, all messages in a thread
        // TODO depth param to indicate whether we want topics or full message threads?
        db.all("SELECT * FROM message order by id asc", function(err, rows) {
            res.setHeader('Access-Control-Allow-Origin', '*');
            res.end(JSON.stringify(rows));
        });
    }
    else if (req.url.startsWith('/send')) {
        // Handle incoming data stream, remote doesn't need a response
        req.on('data', data => {
            try {
                const json = JSON.parse(data);
                db.serialize(function() {
                    const stmt = db.prepare("INSERT INTO message VALUES (?, ?, ?, ?, ?)");
                    console.log(json);
                    // TODO assert data is not empty
                    // TODO parameterize the input put to ensure a well formed ID, what if the board name contains /?
                    const id = json.path + '/' + new Date().toISOString();
                    const depth = id.split('/').length - 1;
                    stmt.run(id, depth, json.data, json.pubkey, json.sig);
                    stmt.finalize();
                });
            }
            catch(e) {
                console.error(e);
            }
            // TODO forward these messages to our peers
        });
    }
    else if (req.url.startsWith('/bootstrap')) {
        // TODO handle bootstrapping requests
        // TODO a peer might ask for a log of all messages sent since X (bootstrapping).
        // if we can serve it, send them the data
    }
});
server.listen(3141, '0.0.0.0');

dht('foo');
/*
// Create POST connection to peers, send them messages when our users post them
//public list of operators, or webrtc p2p communication with socketio signaling
// TODO organize servers in a ring, use hashing to determine token ranges that each server is responsible for?
// TODO overlap ranges to provide replication in case nodes drop out of the ring
const postReq = http.request({hostname: '127.0.0.1', port: 3141, path: '/', method: 'POST'}, res => {});
setInterval(() => {
    const msg = 'hi ' + Math.random();
    postReq.write(JSON.stringify({
    id: '/test',
    message: msg,
    signature: signature(msg),
    }));
}, 1000);
*/