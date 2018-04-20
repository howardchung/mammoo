Quickstart
====
* `go get github.com/codegangsta/gin`
* `bash scripts/start.sh`

// Users run a React app that handles message signing and displays the threaded conversation
// clients will ask for messages from a specific channel, or default '/'
// clients can verify if specific messages are actually from a user by checking the signature against their public key list, e.g. https://github.com/howardchung.keys
// add voting features if desired
// have users do JS hashes in the background (opt-in) to generate a currency/voting/posting power?
// Save git history of each submitted message