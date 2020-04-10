const sqlite = require('sqlite');
const sqlite3 = require('sqlite3');
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const compression = require('compression');
const app = express();
// const dht = require('./dht');
let db;

init();

async function init() {
    db = await sqlite.open({ filename: './database.sqlite', driver: sqlite3.Database });
    await db.run("CREATE TABLE IF NOT EXISTS message (id TEXT, depth INT, data TEXT, pubkey TEXT, sig TEXT)");
    await db.run("CREATE INDEX IF NOT EXISTS message_id_idx ON message(id)");
    // await db.run(`CREATE TABLE accounts()`);
    db.getDatabaseInstance().serialize();
}

app.use(cors());
app.use(compression());
app.use(bodyParser.json());

app.get('/messages', async (req, res) => {
    /*
    if (req.query.board) {
        
    }
    if (req.query.thread) {
        
    }
    */
    // TODO API should support queries for top level messages (boards), all messages within a topic (threads)
    // TODO add endpoints to get all messages in a board, all messages in a thread
    // TODO depth param to indicate whether we want topics or full message threads?
    const rows = await db.all("SELECT * FROM message order by id asc");
    res.json(rows);
});

// Publishes a message to this instance
// TODO make this activitypub compatible?
app.post('/send', async (req, res) => {
    const json = req.body;
    try {
        console.log(json);
        const stmt = await db.prepare("INSERT INTO message VALUES (?, ?, ?, ?, ?)");
        // TODO validate the signature
        // TODO assert data is not empty
        // TODO parameterize the input to ensure a well formed ID, what if the board name contains / or user spoofs path?
        const id = json.path + '/' + new Date().toISOString();
        const depth = id.split('/').length - 1;
        await stmt.run(id, depth, json.data, json.pubkey, json.sig);
        await db.getDatabaseInstance().serialize();
    }
    catch(e) {
        console.error(e);
    }
    // TODO forward these messages to our peers
});

app.get('/bootstrap', (req, res) => {
    // TODO handle bootstrapping requests
    // TODO a peer might ask for a log of all messages sent since X (bootstrapping).
    // if we can serve it, send them the data
});

let domain = '13.66.162.252:3141';
app.post('/createUser', (req, res) => {
  // pass in a name for an account, if the account doesn't exist, create it!
  const account = req.body.account;
  if (account === undefined) {
    return res.status(400).json({msg: 'Bad request. Please make sure "account" is a property in the POST body.'});
  }
  // This should be the publicly accessible hostname of the server
  // create keypair
  // var pair = generateRSAKeypair();
  const pubkey = req.body.pubkey;
  let actorRecord = createActor(account, domain, pubkey);
  let webfingerRecord = createWebfinger(account, domain);
  // const apikey = crypto.randomBytes(16).toString('hex');
  try {
    db.prepare('insert or replace into accounts(name, actor, pubkey, privkey, webfinger) values(?, ?, ?, ?, ?, ?)')
        .run(`${account}@${domain}`, JSON.stringify(actorRecord), pubkey, null, JSON.stringify(webfingerRecord));
    res.status(200);
  }
  catch(e) {
    res.status(200).json({error: e});
  }
});

app.post('/sendMessage', (req, res) => {
  let acct = req.body.acct;
  let message = req.body.message;
  // TODO validate the signature to make sure the sender is who they say they are
  sendCreateMessage(message, acct, domain, req, res);
});

app.listen(3141);

function createActor(name, domain, pubkey) {
  return {
    '@context': [
      'https://www.w3.org/ns/activitystreams',
      'https://w3id.org/security/v1'
    ],

    'id': `https://${domain}/u/${name}`,
    'type': 'Person',
    'preferredUsername': `${name}`,
    'inbox': `https://${domain}/api/inbox`,
    'followers': `https://${domain}/u/${name}/followers`,

    'publicKey': {
      'id': `https://${domain}/u/${name}#main-key`,
      'owner': `https://${domain}/u/${name}`,
      'publicKeyPem': pubkey
    }
  };
}

function createWebfinger(name, domain) {
  return {
    'subject': `acct:${name}@${domain}`,

    'links': [
      {
        'rel': 'self',
        'type': 'application/activity+json',
        'href': `https://${domain}/u/${name}`
      }
    ]
  };
}

function signAndSend(message, name, domain, req, res, targetDomain, inbox) {
  // get the private key
  let db = req.app.get('db');
  let inboxFragment = inbox.replace('https://'+targetDomain,'');
  let result = db.prepare('select privkey from accounts where name = ?').get(`${name}@${domain}`);
  if (result === undefined) {
    console.log(`No record found for ${name}.`);
  }
  else {
    let privkey = result.privkey;
    const signer = crypto.createSign('sha256');
    let d = new Date();
    let stringToSign = `(request-target): post ${inboxFragment}\nhost: ${targetDomain}\ndate: ${d.toUTCString()}`;
    signer.update(stringToSign);
    signer.end();
    const signature = signer.sign(privkey);
    const signature_b64 = signature.toString('base64');
    let header = `keyId="https://${domain}/u/${name}",headers="(request-target) host date",signature="${signature_b64}"`;
    request({
      url: inbox,
      headers: {
        'Host': targetDomain,
        'Date': d.toUTCString(),
        'Signature': header
      },
      method: 'POST',
      json: true,
      body: message
    }, function (error, response){
      console.log(`Sent message to an inbox at ${targetDomain}!`);
      if (error) {
        console.log('Error:', error, response);
      }
      else {
        console.log('Response Status Code:', response.statusCode);
      }
    });
  }
}

function createMessage(text, name, domain) {
  const guidCreate = crypto.randomBytes(16).toString('hex');
  const guidNote = crypto.randomBytes(16).toString('hex');
  let d = new Date();

  // TODO replace IDs with path
  // TODO add support for inReplyTo
  let noteMessage = {
    'id': `https://${domain}/m/${guidNote}`,
    'type': 'Note',
    'published': d.toISOString(),
    'attributedTo': `https://${domain}/u/${name}`,
    'content': text,
    'to': ['https://www.w3.org/ns/activitystreams#Public'],
  };

  let createMessage = {
    '@context': 'https://www.w3.org/ns/activitystreams',

    'id': `https://${domain}/m/${guidCreate}`,
    'type': 'Create',
    'actor': `https://${domain}/u/${name}`,
    'to': ['https://www.w3.org/ns/activitystreams#Public'],

    'object': noteMessage
  };

  return createMessage;
}

function sendCreateMessage(text, name, domain, req, res) {
    let inbox = follower+'/inbox';
    let myURL = new URL(follower);
    let targetDomain = myURL.hostname;
    let message = createMessage(text, name, domain, req, res, follower);
    signAndSend(message, name, domain, req, res, targetDomain, inbox);
    res.status(200);
}

// dht('foo');
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