const DHT = require('bittorrent-dht');
const magnet = require('magnet-uri');
const crypto = require('crypto');

module.exports = (channelName) => {
  const shasum = crypto.createHash('sha1');
  shasum.update(channelName);
  const digest = shasum.digest('hex');
  
  // const uri = 'magnet:?xt=urn:btih:e3811b9539cacff680e418124272177c47477157'
  // const uri = 'magnet:?xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a'
  const uri = 'magnet:?xt=urn:btih:' + digest;
  const parsed = magnet(uri);
  
  console.log(parsed.infoHash); // 'e3811b9539cacff680e418124272177c47477157'
  
  const dht = new DHT();
  
  dht.listen(20000, function () {
    console.log('now listening');
  });
  
  dht.on('peer', function (peer, infoHash, from) {
    console.log('found potential peer ' + peer.host + ':' + peer.port + ' through ' + from.address + ':' + from.port);
  });
  
  dht.announce(parsed.infoHash, 3003, (err) => {
    if (err) {
      console.error(err);
    }
    console.log('announced %s on port %s', parsed.infoHash, 3003);
  });
  
  // find peers for the given torrent info hash
  dht.lookup(parsed.infoHash);
};