var DHT = require('bittorrent-dht')
var magnet = require('magnet-uri')

var crypto = require('crypto');
var shasum = crypto.createHash('sha1');
shasum.update("foo");
var digest = shasum.digest('hex');

// var uri = 'magnet:?xt=urn:btih:e3811b9539cacff680e418124272177c47477157'
// var uri = 'magnet:?xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a'
var uri = 'magnet:?xt=urn:btih:' + digest;
var parsed = magnet(uri)

console.log(parsed.infoHash) // 'e3811b9539cacff680e418124272177c47477157'

var dht = new DHT()

dht.listen(20000, function () {
  console.log('now listening')
})

dht.on('peer', function (peer, infoHash, from) {
  console.log('found potential peer ' + peer.host + ':' + peer.port + ' through ' + from.address + ':' + from.port)
});

dht.announce(parsed.infoHash, 3003, (err) => {
  console.log('announced %s on port %s', parsed.infoHash, 3003);
});

// find peers for the given torrent info hash
dht.lookup(parsed.infoHash);