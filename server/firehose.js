require('dotenv').config();
const axios = require('axios');
const split2 = require('split2');

// Connect to instances.social to pick up instances
// Connect to federated timeline of each one

start();

async function start() {
    const instances = await axios.get('https://instances.social/api/1.0/instances/sample', { headers: { Authorization: 'Bearer ' + process.env.INSTANCES_SOCIAL_KEY }});
    // console.log(instances.data)
    // const host = instances.data.instances[0].name;
    const host = 'mastodon.cloud'; 
    const name = 'http://' + host + '/api/v1/streaming/public';
    console.log(name);
    const response = await axios.get(name, { responseType: 'stream' });
    response.data.pipe(split2()).on('data', (d) => {
        if (d.startsWith('data: ')) {
            console.log(JSON.parse(d.slice(6)));
        }
    });
}