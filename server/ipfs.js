const fs = require('fs');
const os = require('os');
const path = require('path');
const series = require('async/series');
const IPFS = require('ipfs');

const node = new IPFS({
  repo: path.join(os.tmpdir() + '/' + new Date().toString()),
  init: false,
  start: false,
  EXPERIMENTAL: {
    pubsub: false
  }
});

const fileToAdd = {
  path: 'talknet/data.txt',
  content: new Buffer('test file at date ' + new Date().toString()),
};
const fileToAdd2 = {
  path: 'talknet/data.txt',
  content: new Buffer('test file at date ' + new Date().toString()),
};

let fileMultihash;

series([
  /*
   * Display version of js-ipfs
   */
  (cb) => {
    node.version((err, version) => {
      if (err) { return cb(err) }

      console.log('IPFS Version:', version.version);
      cb();
    });
  },
  /*
   * Initialize the repo for this node
   */
  (cb) => node.init({ emptyRepo: true, bits: 2048 }, cb),
  /*
   * Take the node online (bitswap, network and so on)
   */
  (cb) => node.start(cb),
  /*
   * Add a file to IPFS - Complete Files API on:
   * https://github.com/ipfs/interface-ipfs-core/tree/master/API/files
   */
  (cb) => {
    node.files.add(fileToAdd, (err, result) => {
      if (err) { return cb(err) }

      console.log('\nAdded file:');
      console.log(result[0]);
      fileMultihash = result[0].hash;
      cb();
    });
  },
  (cb) => {
    node.files.add(fileToAdd2, (err, result) => {
      if (err) { return cb(err) }

      console.log('\nAdded file:');
      console.log(result[0]);
      fileMultihash = result[0].hash;
      cb();
    });
  },
], (err) => {
  if (err) {
    return console.log(err);
  }
  /*
   * Awesome we've added a file so let's retrieve and
   * display its contents from IPFS
   */
    node.files.cat(fileMultihash, (err, stream) => {
      if (err) { throw err; }
      console.log('\nFile content:');
      stream.pipe(process.stdout);
      stream.on('end', process.exit);
    });
    /*
    node.files.cat('Qmbp6vUYSBZ5oME69w8prYBBDgrGEZ1zLC3hdUYydECk1b', (err, stream) => {
    if (err) { throw err; }
    console.log('\nPreviously added File content:');
    stream.pipe(process.stdout);
    stream.on('end', process.exit);
  });
  */
});