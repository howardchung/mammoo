import path from 'node:path';
import { Readable } from 'node:stream';
import { pathToFileURL } from 'node:url';
import split2 from 'split2';

try {
    process.loadEnvFile(path.join(import.meta.dirname, '.env'));
} catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
}

// Connect to instances.social to pick up instances
// Connect to federated timeline of each one

interface InstancesSocialResponse {
    instances?: Array<{ name?: string }>;
}

export default async function start(): Promise<void> {
    let host = 'mastodon.cloud';

    if (process.env.INSTANCES_SOCIAL_KEY) {
        const instancesRes = await fetch('https://instances.social/api/1.0/instances/sample', {
            headers: { Authorization: 'Bearer ' + process.env.INSTANCES_SOCIAL_KEY }
        });
        if (!instancesRes.ok) {
            throw new Error(`Failed to fetch instances: ${instancesRes.status} ${instancesRes.statusText}`);
        }
        const instances = (await instancesRes.json()) as InstancesSocialResponse;
        host = instances.instances?.[0]?.name || host;
    }

    const name = 'https://' + host + '/api/v1/streaming/public';
    console.log(name);
    const response = await fetch(name);
    if (!response.ok || !response.body) {
        throw new Error(`Failed to stream ${name}: ${response.status} ${response.statusText}`);
    }
    Readable.fromWeb(response.body).pipe(split2()).on('data', (d: string) => {
        if (d.startsWith('data: ')) {
            console.log(JSON.parse(d.slice(6)));
        }
    });
}

if (
    process.argv[1] &&
    (import.meta.url === pathToFileURL(process.argv[1]).href ||
        import.meta.url === pathToFileURL(`${process.argv[1]}.ts`).href)
) {
    start();
}