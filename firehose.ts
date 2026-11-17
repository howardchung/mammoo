import path from 'node:path';
import { Readable } from 'node:stream';
import { pathToFileURL } from 'node:url';
import split2 from 'split2';

try {
    process.loadEnvFile(path.join(import.meta.dirname, '.env'));
} catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
}

interface InstancesSocialResponse {
    instances?: Array<{ name?: string }>;
}

export interface FediverseStatus {
    id: string;
    url?: string;
    uri?: string;
    created_at?: string;
    content?: string;
    account?: {
        acct?: string;
        username?: string;
        display_name?: string;
        url?: string;
    };
    media_attachments?: Array<{
        type?: string;
        url?: string;
    }>;
    tags?: Array<{
        name?: string;
        url?: string;
    }>;
}

export interface FirehoseOptions {
    hosts?: string[];
    token?: string;
    onStatus?: (status: FediverseStatus, host: string) => void | Promise<void>;
}

const DEFAULT_HOSTS = ['fedi.buzz'];

function defaultOnStatus(status: FediverseStatus, host: string): void {
    const author = status.account?.acct || status.account?.username || 'unknown';
    console.log(`[firehose:${host}] @${author}: ${status.content || status.url || status.id}`);
}

async function resolveHosts(explicitHosts?: string[]): Promise<string[]> {
    if (explicitHosts && explicitHosts.length > 0) {
        return explicitHosts;
    }
    if (process.env.FIREHOSE_HOSTS || process.env.FIREHOSE_HOST) {
        const raw = process.env.FIREHOSE_HOSTS || process.env.FIREHOSE_HOST || '';
        const list = raw.split(',').map((h) => h.trim()).filter(Boolean);
        if (list.length > 0) return list;
    }
    if (process.env.INSTANCES_SOCIAL_KEY) {
        try {
            const instancesRes = await fetch('https://instances.social/api/1.0/instances/sample', {
                headers: { Authorization: 'Bearer ' + process.env.INSTANCES_SOCIAL_KEY },
                signal: AbortSignal.timeout(5000),
            });
            if (instancesRes.ok) {
                const instances = (await instancesRes.json()) as InstancesSocialResponse;
                const picked = (instances.instances || [])
                    .map((i) => i.name?.trim())
                    .filter((n): n is string => Boolean(n));
                if (picked.length > 0) return picked.slice(0, 3);
            }
        } catch {
            // Fall back to default host
        }
    }
    return DEFAULT_HOSTS;
}

async function streamHost(
    host: string,
    token: string | undefined,
    onStatus: (status: FediverseStatus, host: string) => void | Promise<void>,
    signal: AbortSignal
): Promise<void> {
    const streamUrl = host.startsWith('http://') || host.startsWith('https://')
        ? host
        : `https://${host}/api/v1/streaming/public`;
    const headers: Record<string, string> = { Accept: 'text/event-stream' };
    if (token) {
        headers.Authorization = `Bearer ${token}`;
    }

    const response = await fetch(streamUrl, { headers, signal });
    if (!response.ok || !response.body) {
        throw new Error(`Failed to stream ${streamUrl}: ${response.status} ${response.statusText}`);
    }

    console.log(`Firehose streaming SSE from ${streamUrl}`);
    let currentEvent = 'update';
    const readable = Readable.fromWeb(response.body);
    readable.on('error', (err: Error) => {
        if (!signal.aborted) {
            console.warn(`Firehose readable error on ${host}:`, err.message);
        }
    });
    const stream = readable.pipe(split2());
    stream.on('data', (line: string) => {
        if (line.startsWith('event: ')) {
            currentEvent = line.slice(7).trim();
            return;
        }
        if (line.startsWith('data: ') && currentEvent === 'update') {
            try {
                const status = JSON.parse(line.slice(6)) as FediverseStatus;
                if (status && status.id) {
                    void onStatus(status, host);
                }
            } catch {
                // Ignore malformed SSE JSON frames
            }
        }
    });
    stream.on('error', (err: Error) => {
        if (!signal.aborted) {
            console.warn(`Firehose SSE error on ${host}:`, err.message);
        }
    });
}

export default async function start(options?: FirehoseOptions): Promise<() => void> {
    const hosts = await resolveHosts(options?.hosts);
    const token = options?.token ?? process.env.MASTODON_ACCESS_TOKEN;
    const onStatus = options?.onStatus ?? defaultOnStatus;
    const controller = new AbortController();

    for (const host of hosts) {
        streamHost(host, token, onStatus, controller.signal).catch((err) => {
            if (!controller.signal.aborted) {
                console.warn(`Firehose stream error (${host}):`, (err as Error).message);
            }
        });
    }

    return () => {
        controller.abort();
    };
}

if (
    process.argv[1] &&
    (import.meta.url === pathToFileURL(process.argv[1]).href ||
        import.meta.url === pathToFileURL(`${process.argv[1]}.ts`).href)
) {
    start().catch((err) => {
        console.error('Firehose error:', err);
        process.exit(1);
    });
}
