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
    pollIntervalMs?: number;
    onStatus?: (status: FediverseStatus, host: string) => void | Promise<void>;
}

const DEFAULT_HOSTS = ['fosstodon.org', 'hachyderm.io'];

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
            // Fall back to default open instances
        }
    }
    return DEFAULT_HOSTS;
}

async function trySseStream(
    host: string,
    token: string | undefined,
    onStatus: (status: FediverseStatus, host: string) => void | Promise<void>
): Promise<boolean> {
    const streamUrl = `https://${host}/api/v1/streaming/public`;
    const headers: Record<string, string> = { Accept: 'text/event-stream' };
    if (token) {
        headers.Authorization = `Bearer ${token}`;
    }
    const response = await fetch(streamUrl, {
        headers,
        signal: AbortSignal.timeout(10000),
    });
    if (!response.ok || !response.body) {
        response.body?.cancel().catch(() => {});
        return false;
    }

    console.log(`Firehose streaming SSE from ${streamUrl}`);
    let currentEvent = 'update';
    const stream = Readable.fromWeb(response.body).pipe(split2());
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
        console.warn(`Firehose SSE error on ${host}:`, err.message);
    });
    return true;
}

async function pollPublicTimeline(
    host: string,
    sinceId: string | undefined,
    onStatus: (status: FediverseStatus, host: string) => void | Promise<void>
): Promise<string | undefined> {
    const params = new URLSearchParams({ limit: '20' });
    if (sinceId) {
        params.set('since_id', sinceId);
    }
    const url = `https://${host}/api/v1/timelines/public?${params.toString()}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
    if (!res.ok) {
        throw new Error(`${url}: ${res.status} ${res.statusText}`);
    }
    const statuses = (await res.json()) as FediverseStatus[];
    if (!Array.isArray(statuses) || statuses.length === 0) {
        return sinceId;
    }

    // API returns newest-first; emit oldest-first and advance sinceId to newest
    const ordered = [...statuses].reverse();
    for (const status of ordered) {
        if (status && status.id) {
            await onStatus(status, host);
        }
    }
    return statuses[0].id || sinceId;
}

export default async function start(options?: FirehoseOptions): Promise<() => void> {
    const hosts = await resolveHosts(options?.hosts);
    const token = options?.token ?? process.env.MASTODON_ACCESS_TOKEN;
    const pollIntervalMs = options?.pollIntervalMs ?? (Number(process.env.FIREHOSE_POLL_MS) || 5000);
    const onStatus = options?.onStatus ?? defaultOnStatus;

    const pollingHosts: string[] = [];
    for (const host of hosts) {
        try {
            const streaming = await trySseStream(host, token, onStatus);
            if (!streaming) {
                pollingHosts.push(host);
            }
        } catch {
            pollingHosts.push(host);
        }
    }

    let timer: NodeJS.Timeout | null = null;
    if (pollingHosts.length > 0) {
        const sinceIds = new Map<string, string>();
        const tick = async () => {
            for (const host of pollingHosts) {
                try {
                    const nextSince = await pollPublicTimeline(host, sinceIds.get(host), onStatus);
                    if (nextSince) {
                        sinceIds.set(host, nextSince);
                    }
                } catch (err) {
                    console.warn(`Firehose poll error (${host}):`, (err as Error).message);
                }
            }
        };

        await tick();
        if (pollIntervalMs > 0) {
            timer = setInterval(() => {
                void tick();
            }, pollIntervalMs);
            timer.unref?.();
        }
    }

    return () => {
        if (timer) clearInterval(timer);
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
