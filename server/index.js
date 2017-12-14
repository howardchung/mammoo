const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./database.sqlite');
const http = require('http');

db.serialize(function() {
    db.run("CREATE TABLE IF NOT EXISTS message (id TEXT, data TEXT, sig TEXT)");
    db.run("CREATE INDEX IF NOT EXISTS message_id_idx ON message(id)");
});

const server = http.createServer((req, res) => {
    if (req.url.startsWith('/messages')) {
        // TODO API should support queries for top level messages (boards), all messages within a topic (threads)
        // client show allow creating a thread, creating a board (just create a new message with the path set)
        // TODO add endpoints to get all messages in a board, all messages in a thread
        // depth param to indicate whether we want topics or full message threads?
        db.all("SELECT * FROM message", function(err, rows) {
            res.setHeader('Access-Control-Allow-Origin', '*');
            res.end(JSON.stringify(rows));
        });
    }
    else if (req.url.startsWith('/send')) {
        // Handle incoming data stream, remote doesn't need a response
        req.on('data', data => {
            try {
                const json = JSON.parse(data);
                //write to a local datastore like sqlite so we can serve our users and other peers
                db.serialize(function() {
                    const stmt = db.prepare("INSERT INTO message VALUES (?, ?, ?)");
                    stmt.run(json.path + '/' + new Date().toISOString(), json.data, json.sig);
                    stmt.finalize();
                });
            }
            catch(e) {
                console.error(e);
            }
            // TODO forward these messages to our peers
        });
    }
    /*
        else if (json.type === 'init') {
        // TODO handle bootstrapping requests
        // TODO a peer might ask for a log of all messages sent since X (bootstrapping).
        // if we can serve it, send them the data
    }
    */
});
server.listen(3141, '0.0.0.0');

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