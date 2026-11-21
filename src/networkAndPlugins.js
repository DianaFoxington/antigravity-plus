"use strict";

/**
 * Antigravity Plus — Network Proxy (HTTP/HTTPS/SOCKS5), Per-Model Quota Rotation,
 * Live Speed/TTFT/Cost Telemetry, and Direct GitHub Plugin/Skill/MCP Installer.
 * Zero external npm dependencies.
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const net = require("net");
const tls = require("tls");
const http = require("http");
const https = require("https");
const zlib = require("zlib");
const crypto = require("crypto");

const PLUS_SETTINGS_PATH = path.join(os.homedir(), ".gemini", "antigravity_plus_settings.json");

const DEFAULT_PLUS_SETTINGS = {
    proxyEnabled: false,
    proxyUrl: "",
    autoRotateOAuth: true,
    oauthQuotaThresholdPct: 1,
    oauthCooldownMinutes: 30,
    autoRotateApiKeys: true,
    apiKeyCooldownMinutes: 10
};

let _cachedPlusSettings = null;

function loadPlusSettings() {
    if (_cachedPlusSettings) return _cachedPlusSettings;
    try {
        if (fs.existsSync(PLUS_SETTINGS_PATH)) {
            const raw = JSON.parse(fs.readFileSync(PLUS_SETTINGS_PATH, "utf8"));
            _cachedPlusSettings = {
                proxyEnabled: Boolean(raw.proxyEnabled),
                proxyUrl: String(raw.proxyUrl || "").trim(),
                autoRotateOAuth: raw.autoRotateOAuth !== false,
                oauthQuotaThresholdPct: Math.max(0, Math.min(50, Number(raw.oauthQuotaThresholdPct ?? 1))),
                oauthCooldownMinutes: Math.max(1, Math.min(1440, Number(raw.oauthCooldownMinutes ?? 30))),
                autoRotateApiKeys: raw.autoRotateApiKeys !== false,
                apiKeyCooldownMinutes: Math.max(1, Math.min(1440, Number(raw.apiKeyCooldownMinutes ?? 10)))
            };
            return _cachedPlusSettings;
        }
    } catch {}
    _cachedPlusSettings = { ...DEFAULT_PLUS_SETTINGS };
    savePlusSettings(_cachedPlusSettings);
    return _cachedPlusSettings;
}

function savePlusSettings(nextPartial) {
    const cur = loadPlusSettings();
    const merged = {
        ...cur,
        ...(nextPartial || {})
    };
    merged.proxyEnabled = Boolean(merged.proxyEnabled);
    merged.proxyUrl = String(merged.proxyUrl || "").trim();
    merged.autoRotateOAuth = merged.autoRotateOAuth !== false;
    merged.oauthQuotaThresholdPct = Math.max(0, Math.min(50, Number(merged.oauthQuotaThresholdPct ?? 1)));
    merged.oauthCooldownMinutes = Math.max(1, Math.min(1440, Number(merged.oauthCooldownMinutes ?? 30)));
    merged.autoRotateApiKeys = merged.autoRotateApiKeys !== false;
    merged.apiKeyCooldownMinutes = Math.max(1, Math.min(1440, Number(merged.apiKeyCooldownMinutes ?? 10)));

    _cachedPlusSettings = merged;
    try {
        fs.mkdirSync(path.dirname(PLUS_SETTINGS_PATH), { recursive: true });
        fs.writeFileSync(PLUS_SETTINGS_PATH, JSON.stringify(merged, null, 2), "utf8");
    } catch {}
    return merged;
}

function getProxyEnvForLanguageServer() {
    const s = loadPlusSettings();
    if (!s.proxyEnabled || !s.proxyUrl) {
        return { enabled: false };
    }
    return {
        enabled: true,
        proxyUrl: s.proxyUrl,
        noProxy: "localhost,127.0.0.1,::1"
    };
}

// ---------------------------------------------------------------------------
// Pure-Node HTTP CONNECT & SOCKS5 Proxy Tunneling
// ---------------------------------------------------------------------------
function parseProxyConfig(overrideProxyUrl = null) {
    let raw = overrideProxyUrl;
    if (raw === null) {
        const s = loadPlusSettings();
        if (!s.proxyEnabled || !s.proxyUrl) return null;
        raw = s.proxyUrl;
    }
    raw = String(raw || "").trim();
    if (!raw) return null;
    if (!/^[a-zA-Z0-9+.-]+:\/\//.test(raw)) {
        raw = `http://${raw}`;
    }
    const u = new URL(raw);
    const proto = u.protocol.replace(/:$/, "").toLowerCase();
    return {
        protocol: proto,
        host: u.hostname,
        port: Number(u.port) || (proto.startsWith("socks") ? 1080 : (proto === "https" ? 443 : 8080)),
        username: u.username ? decodeURIComponent(u.username) : "",
        password: u.password ? decodeURIComponent(u.password) : ""
    };
}

function isLocalhostHost(hostname) {
    const h = String(hostname || "").toLowerCase();
    return h === "localhost" || h === "127.0.0.1" || h === "::1" || h === "[::1]";
}

function openHttpConnectTunnel(proxy, targetHost, targetPort, timeoutMs = 15000) {
    return new Promise((resolve, reject) => {
        const connectSocket = proxy.protocol === "https"
            ? tls.connect({ host: proxy.host, port: proxy.port, servername: proxy.host, rejectUnauthorized: false })
            : net.connect({ host: proxy.host, port: proxy.port });

        let settled = false;
        const fail = (err) => {
            if (settled) return;
            settled = true;
            try { connectSocket.destroy(); } catch {}
            reject(err);
        };

        connectSocket.setTimeout(timeoutMs, () => fail(new Error("Proxy CONNECT timed out")));
        connectSocket.once("error", fail);

        const onConnected = () => {
            let reqStr = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n`;
            if (proxy.username || proxy.password) {
                const auth = Buffer.from(`${proxy.username}:${proxy.password}`).toString("base64");
                reqStr += `Proxy-Authorization: Basic ${auth}\r\n`;
            }
            reqStr += "Connection: keep-alive\r\n\r\n";
            connectSocket.write(reqStr);

            let headerBuf = Buffer.alloc(0);
            const onData = (chunk) => {
                headerBuf = Buffer.concat([headerBuf, chunk]);
                const endIdx = headerBuf.indexOf("\r\n\r\n");
                if (endIdx === -1) {
                    if (headerBuf.length > 16384) fail(new Error("Proxy CONNECT header too large"));
                    return;
                }
                connectSocket.removeListener("data", onData);
                const statusLine = headerBuf.slice(0, headerBuf.indexOf("\r\n")).toString("utf8");
                const m = /^HTTP\/1\.[01]\s+(\d+)/i.exec(statusLine);
                const code = m ? Number(m[1]) : 0;
                if (code !== 200) {
                    return fail(new Error(`Proxy CONNECT failed (${statusLine})`));
                }
                const extra = headerBuf.slice(endIdx + 4);
                if (extra.length > 0) connectSocket.unshift(extra);
                connectSocket.setTimeout(0);
                connectSocket.removeListener("error", fail);
                connectSocket.on("error", () => {});
                settled = true;
                resolve(connectSocket);
            };
            connectSocket.on("data", onData);
        };

        connectSocket.once(proxy.protocol === "https" ? "secureConnect" : "connect", onConnected);
    });
}

function openSocks5Tunnel(proxy, targetHost, targetPort, timeoutMs = 15000) {
    return new Promise((resolve, reject) => {
        const sock = net.connect({ host: proxy.host, port: proxy.port });
        let settled = false;
        const fail = (err) => {
            if (settled) return;
            settled = true;
            try { sock.destroy(); } catch {}
            reject(err);
        };

        sock.setTimeout(timeoutMs, () => fail(new Error("SOCKS5 proxy timed out")));
        sock.once("error", fail);

        const readExact = (n, cb) => {
            let buf = Buffer.alloc(0);
            const onData = (chunk) => {
                buf = Buffer.concat([buf, chunk]);
                if (buf.length >= n) {
                    sock.removeListener("data", onData);
                    const head = buf.slice(0, n);
                    const rest = buf.slice(n);
                    if (rest.length > 0) sock.unshift(rest);
                    cb(head);
                }
            };
            sock.on("data", onData);
        };

        sock.once("connect", () => {
            const hasAuth = Boolean(proxy.username || proxy.password);
            const greeting = hasAuth ? Buffer.from([0x05, 0x02, 0x00, 0x02]) : Buffer.from([0x05, 0x01, 0x00]);
            sock.write(greeting);

            readExact(2, (methodResp) => {
                if (methodResp[0] !== 0x05) return fail(new Error("Invalid SOCKS5 proxy response"));
                const chosen = methodResp[1];

                const sendConnectCmd = () => {
                    const cleanHost = String(targetHost || "").replace(/^\[|\]$/g, "");
                    const portBuf = Buffer.alloc(2);
                    portBuf.writeUInt16BE(Number(targetPort), 0);
                    const ipVer = net.isIP(cleanHost);
                    let addrPart;
                    if (ipVer === 4) {
                        addrPart = Buffer.from([0x01, ...cleanHost.split(".").map(x => Number(x) & 0xff)]);
                    } else if (ipVer === 6) {
                        // Expand IPv6 into 16 bytes
                        const [left, right] = cleanHost.split("::");
                        const lParts = left ? left.split(":").filter(Boolean) : [];
                        const rParts = right !== undefined ? (right ? right.split(":").filter(Boolean) : []) : [];
                        const fill = right !== undefined ? Math.max(0, 8 - lParts.length - rParts.length) : 0;
                        const groups = [...lParts, ...Array(fill).fill("0"), ...rParts];
                        const v6 = Buffer.alloc(17);
                        v6[0] = 0x04;
                        for (let gi = 0; gi < 8; gi++) {
                            v6.writeUInt16BE(parseInt(groups[gi] || "0", 16) & 0xffff, 1 + gi * 2);
                        }
                        addrPart = v6;
                    } else {
                        const hostBytes = Buffer.from(cleanHost, "utf8").slice(0, 255);
                        // ATYP = 0x03 (domain name, resolved remotely by SOCKS5 server -> leak-free DNS!)
                        addrPart = Buffer.concat([Buffer.from([0x03, hostBytes.length]), hostBytes]);
                    }
                    const req = Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), addrPart, portBuf]);
                    sock.write(req);

                    const finishSocks = () => {
                        sock.setTimeout(0);
                        sock.removeListener("error", fail);
                        sock.on("error", () => {});
                        settled = true;
                        resolve(sock);
                    };

                    readExact(4, (hdr) => {
                        if (hdr[1] !== 0x00) {
                            return fail(new Error(`SOCKS5 connect rejected (code 0x${hdr[1].toString(16)})`));
                        }
                        const atyp = hdr[3];
                        if (atyp === 0x01) {
                            readExact(4 + 2, finishSocks);
                        } else if (atyp === 0x04) {
                            readExact(16 + 2, finishSocks);
                        } else if (atyp === 0x03) {
                            readExact(1, (lenBuf) => {
                                readExact(lenBuf[0] + 2, finishSocks);
                            });
                        } else {
                            fail(new Error("Unknown SOCKS5 address type"));
                        }
                    });
                };

                if (chosen === 0x00) {
                    sendConnectCmd();
                } else if (chosen === 0x02 && hasAuth) {
                    const uBuf = Buffer.from(proxy.username, "utf8");
                    const pBuf = Buffer.from(proxy.password, "utf8");
                    sock.write(Buffer.concat([Buffer.from([0x01, uBuf.length]), uBuf, Buffer.from([pBuf.length]), pBuf]));
                    readExact(2, (authResp) => {
                        if (authResp[1] !== 0x00) return fail(new Error("SOCKS5 authentication failed"));
                        sendConnectCmd();
                    });
                } else {
                    fail(new Error("SOCKS5 proxy rejected authentication methods"));
                }
            });
        });
    });
}

class TunnelHttpsAgent extends https.Agent {
    constructor(proxyCfg) {
        super({ keepAlive: false });
        this.proxyCfg = proxyCfg;
    }
    createConnection(options, callback) {
        const targetHost = options.hostname || options.host || "localhost";
        const targetPort = Number(options.port) || 443;
        const opener = this.proxyCfg.protocol.startsWith("socks")
            ? openSocks5Tunnel(this.proxyCfg, targetHost, targetPort)
            : openHttpConnectTunnel(this.proxyCfg, targetHost, targetPort);

        opener.then((rawSock) => {
            const tlsSock = tls.connect({
                socket: rawSock,
                servername: options.servername || targetHost,
                rejectUnauthorized: options.rejectUnauthorized !== false
            });
            callback(null, tlsSock);
        }).catch((err) => callback(err));
    }
}

class TunnelHttpAgent extends http.Agent {
    constructor(proxyCfg) {
        super({ keepAlive: false });
        this.proxyCfg = proxyCfg;
    }
    createConnection(options, callback) {
        const targetHost = options.hostname || options.host || "localhost";
        const targetPort = Number(options.port) || 80;
        const opener = this.proxyCfg.protocol.startsWith("socks")
            ? openSocks5Tunnel(this.proxyCfg, targetHost, targetPort)
            : openHttpConnectTunnel(this.proxyCfg, targetHost, targetPort);
        opener.then((rawSock) => callback(null, rawSock)).catch((err) => callback(err));
    }
}

function createProxiedRequest(isHttps, reqOptions, onResponse, overrideProxyUrl = null) {
    const host = reqOptions.hostname || reqOptions.host || "";
    const proxyCfg = isLocalhostHost(host) ? null : parseProxyConfig(overrideProxyUrl);
    const clonedOpts = { ...reqOptions };
    if (proxyCfg) {
        clonedOpts.agent = isHttps ? new TunnelHttpsAgent(proxyCfg) : new TunnelHttpAgent(proxyCfg);
    }
    return (isHttps ? https : http).request(clonedOpts, onResponse);
}

function downloadBufferWithProxy(urlStr, maxRedirects = 5, extraHeaders = {}, overrideProxyUrl = null) {
    return new Promise((resolve, reject) => {
        if (maxRedirects < 0) return reject(new Error("Too many redirects"));
        let u;
        try { u = new URL(urlStr); } catch (e) { return reject(e); }
        const isHttps = u.protocol === "https:";
        const req = createProxiedRequest(isHttps, {
            hostname: u.hostname,
            port: u.port || (isHttps ? 443 : 80),
            path: u.pathname + u.search,
            method: "GET",
            headers: {
                "User-Agent": "Antigravity-Plus/1.0",
                ...extraHeaders
            },
            timeout: 30000
        }, (res) => {
            if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                res.resume();
                const nextUrl = new URL(res.headers.location, urlStr).toString();
                return resolve(downloadBufferWithProxy(nextUrl, maxRedirects - 1, extraHeaders, overrideProxyUrl));
            }
            if (res.statusCode !== 200) {
                let errBody = "";
                res.on("data", d => { if (errBody.length < 512) errBody += d.toString("utf8"); });
                res.on("end", () => reject(new Error(`HTTP ${res.statusCode} from ${u.hostname}${errBody ? `: ${errBody.slice(0, 140)}` : ""}`)));
                return;
            }
            const chunks = [];
            res.on("data", (d) => chunks.push(d));
            res.on("end", () => resolve(Buffer.concat(chunks)));
            res.on("error", reject);
        }, overrideProxyUrl);

        req.on("timeout", () => { req.destroy(); reject(new Error("Request timed out")); });
        req.on("error", reject);
        req.end();
    });
}

async function testProxyConnectionLive(proxyUrlToTest) {
    const clean = String(proxyUrlToTest || "").trim();
    if (!clean) {
        return { ok: false, latencyMs: 0, message: "Enter a Proxy URL first (e.g. http://127.0.0.1:10809 or socks5://127.0.0.1:10808)" };
    }
    let parsed;
    try {
        parsed = parseProxyConfig(clean);
    } catch (e) {
        return { ok: false, latencyMs: 0, message: `Invalid Proxy URL: ${e.message}` };
    }
    const t0 = Date.now();
    return new Promise((resolve) => {
        const req = createProxiedRequest(true, {
            hostname: "generativelanguage.googleapis.com",
            port: 443,
            path: "/$discovery/rest?version=v1beta",
            method: "HEAD",
            timeout: 10000
        }, (res) => {
            res.resume();
            const ms = Date.now() - t0;
            resolve({
                ok: Boolean(res.statusCode && res.statusCode < 500),
                latencyMs: ms,
                message: `Proxy OK (${parsed.protocol.toUpperCase()} -> Google TLS in ${ms}ms, HTTP ${res.statusCode})`
            });
        }, clean);
        req.on("timeout", () => { req.destroy(); resolve({ ok: false, latencyMs: Date.now() - t0, message: "Proxy connection timed out (10s)" }); });
        req.on("error", (err) => resolve({ ok: false, latencyMs: Date.now() - t0, message: `Proxy failed: ${err.message}` }));
        req.end();
    });
}

// ---------------------------------------------------------------------------
// Per-(Account, Model) Quota Exhaustion & Auto-Rotation Engine
// ---------------------------------------------------------------------------
// API-Key mode: key = `${providerId}::${keyMask}::${normModel}`
const apiKeyModelCooldowns = new Map();
// Google OAuth mode: key = `${slotId}::${normModel}` -> { remainingFraction, displayName, exhaustedUntilTs, updatedAt }
const oauthSlotModelQuotas = new Map();

function normalizeModelBucketKey(raw) {
    return String(raw || "")
        .toLowerCase()
        .replace(/-(low|medium|high|max)$/i, "")
        .replace(/\s*\((low|medium|high|max|thinking)\)\s*/gi, "")
        .replace(/[^a-z0-9]/g, "");
}

function maskKeyShort(k) {
    const s = String(k || "");
    if (s.length <= 10) return "key";
    return `${s.slice(0, 6)}..${s.slice(-4)}`;
}

function getOrderedApiKeysForModel(providerId, candidateKeys, modelId) {
    if (!Array.isArray(candidateKeys) || candidateKeys.length <= 1) return candidateKeys || [];
    const settings = loadPlusSettings();
    if (!settings.autoRotateApiKeys) return candidateKeys;

    const now = Date.now();
    const normM = normalizeModelBucketKey(modelId);
    const available = [];
    const cooling = [];

    for (const key of candidateKeys) {
        const mapKey = `${providerId}::${maskKeyShort(key)}::${normM}`;
        const entry = apiKeyModelCooldowns.get(mapKey);
        if (entry && entry.untilTs > now) {
            cooling.push({ key, untilTs: entry.untilTs });
        } else {
            if (entry) apiKeyModelCooldowns.delete(mapKey);
            available.push(key);
        }
    }

    if (available.length > 0) {
        // Put available keys first, followed by earliest-expiring cooling keys as last-resort fallback
        cooling.sort((a, b) => a.untilTs - b.untilTs);
        return [...available, ...cooling.map(c => c.key)];
    }
    cooling.sort((a, b) => a.untilTs - b.untilTs);
    return cooling.map(c => c.key);
}

function markApiKeyModelQuotaExhausted(providerId, apiKey, modelId, reason = "429") {
    const settings = loadPlusSettings();
    if (!settings.autoRotateApiKeys || !apiKey || !modelId) return;
    const normM = normalizeModelBucketKey(modelId);
    const mask = maskKeyShort(apiKey);
    const mapKey = `${providerId}::${mask}::${normM}`;
    const untilTs = Date.now() + settings.apiKeyCooldownMinutes * 60 * 1000;
    apiKeyModelCooldowns.set(mapKey, {
        providerId,
        keyMask: mask,
        modelId,
        reason,
        untilTs
    });
}

function recordOAuthSlotQuotaSummary(slotId, groupsArray) {
    if (!slotId || !Array.isArray(groupsArray)) return;
    const now = Date.now();
    for (const grp of groupsArray) {
        const buckets = Array.isArray(grp?.buckets) ? grp.buckets : [];
        for (const b of buckets) {
            const rem = b?.remaining?.case === "remainingFraction" ? Number(b.remaining.value) : null;
            if (rem === null || Number.isNaN(rem)) continue;
            const ids = [b.bucketId, b.displayName].filter(Boolean);
            for (const rawId of ids) {
                const norm = normalizeModelBucketKey(rawId);
                if (!norm) continue;
                const key = `${slotId}::${norm}`;
                const prev = oauthSlotModelQuotas.get(key);
                oauthSlotModelQuotas.set(key, {
                    slotId,
                    modelLabel: b.displayName || b.bucketId || rawId,
                    remainingFraction: rem,
                    exhaustedUntilTs: rem <= 0 ? (prev?.exhaustedUntilTs || (now + loadPlusSettings().oauthCooldownMinutes * 60000)) : 0,
                    updatedAt: now
                });
            }
        }
    }
}

function markOAuthSlotModelExhausted(slotId, modelHint) {
    if (!slotId) return;
    const norm = normalizeModelBucketKey(modelHint || "all");
    const settings = loadPlusSettings();
    const key = `${slotId}::${norm}`;
    oauthSlotModelQuotas.set(key, {
        slotId,
        modelLabel: modelHint || "Active Model",
        remainingFraction: 0,
        exhaustedUntilTs: Date.now() + settings.oauthCooldownMinutes * 60000,
        updatedAt: Date.now()
    });
}

function isOAuthSlotExhaustedForModel(slotId, modelHint, settings) {
    const norm = normalizeModelBucketKey(modelHint);
    if (!norm) return false;
    const now = Date.now();
    const thresholdFrac = (settings.oauthQuotaThresholdPct || 0) / 100;

    // Exact or prefix/substring bucket match (e.g., "Gemini 4 Carbon (High)" <-> "gemini4carbon")
    for (const [k, v] of oauthSlotModelQuotas.entries()) {
        if (!k.startsWith(`${slotId}::`)) continue;
        const bucketNorm = k.slice(slotId.length + 2);
        if (bucketNorm === norm || norm.includes(bucketNorm) || bucketNorm.includes(norm)) {
            if (v.exhaustedUntilTs && v.exhaustedUntilTs > now) return true;
            if (typeof v.remainingFraction === "number" && v.remainingFraction <= thresholdFrac) {
                // Expire stale cached 0% after oauthCooldownMinutes so natural quota replenishment works!
                if (now - v.updatedAt < settings.oauthCooldownMinutes * 60000) {
                    return true;
                }
            }
        }
    }
    return false;
}

function findNextAvailableOAuthSlotForModel(slots, activeSlotId, modelHint, forceSwitchFromCurrent = false) {
    const settings = loadPlusSettings();
    if (!settings.autoRotateOAuth || !Array.isArray(slots) || slots.length <= 1) {
        return null;
    }
    const validSlots = slots.filter(s => s && s.hasSavedCreds);
    if (validSlots.length <= 1) return null;

    if (!forceSwitchFromCurrent && !isOAuthSlotExhaustedForModel(activeSlotId, modelHint, settings)) {
        return null;
    }

    const startIdx = Math.max(0, validSlots.findIndex(s => s.id === activeSlotId));
    for (let offset = 1; offset < validSlots.length; offset++) {
        const candidate = validSlots[(startIdx + offset) % validSlots.length];
        if (!isOAuthSlotExhaustedForModel(candidate.id, modelHint, settings)) {
            return candidate;
        }
    }
    return null;
}

function getQuotaCooldownsOverview() {
    const now = Date.now();
    const apiItems = [];
    for (const [k, v] of apiKeyModelCooldowns.entries()) {
        if (v.untilTs <= now) {
            apiKeyModelCooldowns.delete(k);
            continue;
        }
        apiItems.push({
            providerId: v.providerId,
            keyMask: v.keyMask,
            modelId: v.modelId,
            remainingSec: Math.ceil((v.untilTs - now) / 1000)
        });
    }
    const oauthItems = [];
    const seenOAuth = new Set();
    for (const [, v] of oauthSlotModelQuotas.entries()) {
        if ((v.exhaustedUntilTs && v.exhaustedUntilTs > now) || v.remainingFraction <= 0) {
            const sig = `${v.slotId}::${v.modelLabel}`;
            if (seenOAuth.has(sig)) continue;
            seenOAuth.add(sig);
            oauthItems.push({
                slotId: v.slotId,
                modelLabel: v.modelLabel,
                remainingPct: Math.round((v.remainingFraction || 0) * 100)
            });
        }
    }
    return { apiItems, oauthItems };
}

function clearAllQuotaCooldowns() {
    apiKeyModelCooldowns.clear();
    oauthSlotModelQuotas.clear();
}

// ---------------------------------------------------------------------------
// Live Speed (`tok/s`), Latency (`TTFT ms`), & Cost Telemetry
// ---------------------------------------------------------------------------
const BUILTIN_COST_PER_1M = [
    { match: /claude-opus-4/i, inUsd: 15.0, outUsd: 75.0 },
    { match: /claude-sonnet-4/i, inUsd: 3.0, outUsd: 15.0 },
    { match: /claude-haiku/i, inUsd: 0.8, outUsd: 4.0 },
    { match: /gemini-4-carbon|gemini-2\.5-pro|gemini-3.*pro/i, inUsd: 1.25, outUsd: 10.0 },
    { match: /gemini-4-argon/i, inUsd: 0.5, outUsd: 3.0 },
    { match: /gemini-4-hydrogen|flash/i, inUsd: 0.15, outUsd: 0.60 },
    { match: /gpt-4o-mini/i, inUsd: 0.15, outUsd: 0.60 },
    { match: /gpt-4o|gpt-4\.1|gpt-5/i, inUsd: 2.0, outUsd: 8.0 },
    { match: /deepseek/i, inUsd: 0.27, outUsd: 1.10 },
    { match: /gemma|llama|qwen/i, inUsd: 0.10, outUsd: 0.30 }
];

const liveTelemetry = {
    isStreaming: false,
    totalRequests: 0,
    totalPromptTokens: 0,
    totalCompletionTokens: 0,
    totalCostUsd: 0,
    lastTokPerSec: 0,
    lastTtftMs: 0,
    lastModel: "",
    lastProvider: "",
    recentSpeedSamples: []
};

const telemetrySubscribers = new Set();
let _lastTickBroadcastTs = 0;

function broadcastTelemetrySnapshot() {
    if (telemetrySubscribers.size === 0) return;
    const payload = `data: ${JSON.stringify(getTelemetrySnapshot())}\n\n`;
    for (const subRes of Array.from(telemetrySubscribers)) {
        try {
            subRes.write(payload);
        } catch {
            telemetrySubscribers.delete(subRes);
        }
    }
}

function subscribeTelemetrySse(res) {
    res.writeHead(200, {
        "Content-Type": "text/event-stream; charset=UTF-8",
        "Cache-Control": "no-cache, no-transform",
        "Connection": "keep-alive",
        "Access-Control-Allow-Origin": "*"
    });
    res.write(`data: ${JSON.stringify(getTelemetrySnapshot())}\n\n`);
    telemetrySubscribers.add(res);
    res.on("close", () => telemetrySubscribers.delete(res));
    res.on("error", () => telemetrySubscribers.delete(res));
}

function tickStreamingTelemetry({ modelId, providerName, requestStartTs, firstTokenTs, streamedTokensSoFar }) {
    const now = Date.now();
    if (now - _lastTickBroadcastTs < 120) return;
    _lastTickBroadcastTs = now;

    const cTok = Math.max(1, Number(streamedTokensSoFar) || 1);
    const fTs = firstTokenTs || now;
    const ttft = requestStartTs ? Math.max(1, fTs - requestStartTs) : liveTelemetry.lastTtftMs;
    const elapsedMs = Math.max(80, now - fTs);
    const liveSpeed = Number(((cTok / elapsedMs) * 1000).toFixed(1));

    liveTelemetry.isStreaming = true;
    if (liveSpeed > 0) liveTelemetry.lastTokPerSec = liveSpeed;
    if (ttft > 0) liveTelemetry.lastTtftMs = ttft;
    if (modelId) liveTelemetry.lastModel = modelId;
    if (providerName) liveTelemetry.lastProvider = providerName;

    broadcastTelemetrySnapshot();
}

function estimateCostUsd(modelId, promptTokens, completionTokens, customCostCfg = null) {
    let inRate = 0;
    let outRate = 0;
    if (customCostCfg && (typeof customCostCfg.input === "number" || typeof customCostCfg.output === "number")) {
        inRate = Number(customCostCfg.input) || 0;
        outRate = Number(customCostCfg.output) || 0;
    } else {
        const hit = BUILTIN_COST_PER_1M.find(r => r.match.test(String(modelId || "")));
        if (hit) {
            inRate = hit.inUsd;
            outRate = hit.outUsd;
        }
    }
    return ((Math.max(0, promptTokens) / 1000000) * inRate) + ((Math.max(0, completionTokens) / 1000000) * outRate);
}

function recordRequestTelemetry({ modelId, providerName, requestStartTs, firstTokenTs, endTs, promptTokens, completionTokens, customCostCfg }) {
    const pTok = Math.max(0, Number(promptTokens) || 0);
    const cTok = Math.max(0, Number(completionTokens) || 0);
    const now = endTs || Date.now();
    const ttft = firstTokenTs && requestStartTs ? Math.max(1, firstTokenTs - requestStartTs) : 0;
    const genWindowMs = firstTokenTs ? Math.max(50, now - firstTokenTs) : Math.max(50, now - (requestStartTs || now));
    const tokPerSec = cTok > 0 ? Number(((cTok / genWindowMs) * 1000).toFixed(1)) : 0;
    const cost = estimateCostUsd(modelId, pTok, cTok, customCostCfg);

    liveTelemetry.isStreaming = false;
    liveTelemetry.totalRequests += 1;
    liveTelemetry.totalPromptTokens += pTok;
    liveTelemetry.totalCompletionTokens += cTok;
    liveTelemetry.totalCostUsd = Number((liveTelemetry.totalCostUsd + cost).toFixed(6));
    if (tokPerSec > 0) {
        liveTelemetry.lastTokPerSec = tokPerSec;
        liveTelemetry.recentSpeedSamples.push(tokPerSec);
        if (liveTelemetry.recentSpeedSamples.length > 20) liveTelemetry.recentSpeedSamples.shift();
    }
    if (ttft > 0) liveTelemetry.lastTtftMs = ttft;
    if (modelId) liveTelemetry.lastModel = modelId;
    if (providerName) liveTelemetry.lastProvider = providerName;

    broadcastTelemetrySnapshot();
}

function getTelemetrySnapshot() {
    const samples = liveTelemetry.recentSpeedSamples;
    const avgSpeed = samples.length > 0
        ? Number((samples.reduce((a, b) => a + b, 0) / samples.length).toFixed(1))
        : 0;
    return {
        isStreaming: liveTelemetry.isStreaming,
        totalRequests: liveTelemetry.totalRequests,
        totalPromptTokens: liveTelemetry.totalPromptTokens,
        totalCompletionTokens: liveTelemetry.totalCompletionTokens,
        totalCostUsd: liveTelemetry.totalCostUsd,
        lastTokPerSec: liveTelemetry.lastTokPerSec,
        avgTokPerSec: avgSpeed,
        lastTtftMs: liveTelemetry.lastTtftMs,
        lastModel: liveTelemetry.lastModel,
        lastProvider: liveTelemetry.lastProvider
    };
}

function resetTelemetrySnapshot() {
    liveTelemetry.isStreaming = false;
    liveTelemetry.totalRequests = 0;
    liveTelemetry.totalPromptTokens = 0;
    liveTelemetry.totalCompletionTokens = 0;
    liveTelemetry.totalCostUsd = 0;
    liveTelemetry.lastTokPerSec = 0;
    liveTelemetry.lastTtftMs = 0;
    liveTelemetry.recentSpeedSamples = [];
    broadcastTelemetrySnapshot();
}

// ---------------------------------------------------------------------------
// Direct GitHub URL Plugin / Skill / MCP Installer
// ---------------------------------------------------------------------------
function parseGitHubRepoSpec(rawInput) {
    let s = String(rawInput || "").trim().replace(/\/+$/, "");
    if (!s) throw new Error("Enter a GitHub repository URL or owner/repo.");

    // Direct .zip URL
    if (/^https?:\/\/.+\.zip(\?.*)?$/i.test(s)) {
        const baseName = path.basename(new URL(s).pathname, ".zip").replace(/[^a-zA-Z0-9_-]/g, "-").toLowerCase();
        return { directZipUrl: s, owner: "github", repo: baseName || "custom-plugin", branch: "", subPath: "" };
    }

    // Short `owner/repo`
    if (/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(s)) {
        const [owner, repo] = s.split("/");
        return { owner, repo: repo.replace(/\.git$/i, ""), branch: "", subPath: "" };
    }

    let u;
    try { u = new URL(s); } catch {
        throw new Error("Invalid GitHub URL. Example: https://github.com/owner/repo");
    }
    if (!u.hostname.toLowerCase().includes("github.com")) {
        throw new Error("URL must be a github.com repository or a direct .zip archive URL.");
    }
    const parts = u.pathname.split("/").filter(Boolean);
    if (parts.length < 2) {
        throw new Error("GitHub URL must include owner and repository (https://github.com/owner/repo).");
    }
    const owner = parts[0];
    const repo = parts[1].replace(/\.git$/i, "");
    let branch = "";
    let subPath = "";
    if ((parts[2] === "tree" || parts[2] === "blob") && parts.length >= 4) {
        branch = parts[3];
        subPath = parts.slice(4).join("/");
        if (parts[2] === "blob" && subPath.toLowerCase().endsWith("/skill.md")) {
            subPath = path.posix.dirname(subPath);
            if (subPath === ".") subPath = "";
        }
    }
    return { owner, repo, branch, subPath };
}

function extractZipToFolderWithStrip(zipBuf, destDir, subPathFilter = "") {
    let eocdOffset = -1;
    const minOffset = Math.max(0, zipBuf.length - 65557);
    for (let i = zipBuf.length - 22; i >= minOffset; i--) {
        if (zipBuf.readUInt32LE(i) === 0x06054b50) {
            eocdOffset = i;
            break;
        }
    }
    if (eocdOffset < 0) throw new Error("Downloaded archive is not a valid ZIP file.");

    const totalEntries = zipBuf.readUInt16LE(eocdOffset + 10);
    const cdOffset = zipBuf.readUInt32LE(eocdOffset + 16);

    const rawEntries = [];
    let ptr = cdOffset;
    for (let i = 0; i < totalEntries; i++) {
        if (ptr + 46 > zipBuf.length || zipBuf.readUInt32LE(ptr) !== 0x02014b50) break;
        const method = zipBuf.readUInt16LE(ptr + 10);
        const compSize = zipBuf.readUInt32LE(ptr + 20);
        const nameLen = zipBuf.readUInt16LE(ptr + 28);
        const extraLen = zipBuf.readUInt16LE(ptr + 30);
        const commentLen = zipBuf.readUInt16LE(ptr + 32);
        const localHeaderOffset = zipBuf.readUInt32LE(ptr + 42);
        const rawName = zipBuf.slice(ptr + 46, ptr + 46 + nameLen).toString("utf8").replace(/\\/g, "/").replace(/^\/+/, "");
        ptr += 46 + nameLen + extraLen + commentLen;
        if (rawName) rawEntries.push({ rawName, method, compSize, localHeaderOffset });
    }

    // Detect common single root directory (standard in GitHub codeload zipballs: `<repo>-<sha>/`)
    const firstSegs = new Set(rawEntries.map(e => e.rawName.split("/")[0]).filter(Boolean));
    const stripRoot = firstSegs.size === 1 && rawEntries.some(e => e.rawName.includes("/"))
        ? `${Array.from(firstSegs)[0]}/`
        : "";

    const cleanSub = subPathFilter ? subPathFilter.replace(/^\/+|\/+$/g, "") + "/" : "";
    const resolvedDest = path.resolve(destDir);
    fs.mkdirSync(resolvedDest, { recursive: true });

    let writtenFiles = 0;
    for (const ent of rawEntries) {
        let rel = stripRoot && ent.rawName.startsWith(stripRoot) ? ent.rawName.slice(stripRoot.length) : ent.rawName;
        if (!rel) continue;
        if (cleanSub) {
            if (!rel.startsWith(cleanSub)) continue;
            rel = rel.slice(cleanSub.length);
            if (!rel) continue;
        }
        const outPath = path.resolve(resolvedDest, rel);
        if (outPath !== resolvedDest && !outPath.startsWith(resolvedDest + path.sep)) continue;

        if (rel.endsWith("/")) {
            fs.mkdirSync(outPath, { recursive: true });
            continue;
        }
        if (ent.localHeaderOffset + 30 > zipBuf.length || zipBuf.readUInt32LE(ent.localHeaderOffset) !== 0x04034b50) {
            continue;
        }
        if (ent.method !== 0 && ent.method !== 8) {
            continue;
        }
        const lNameLen = zipBuf.readUInt16LE(ent.localHeaderOffset + 26);
        const lExtraLen = zipBuf.readUInt16LE(ent.localHeaderOffset + 28);
        const dataStart = ent.localHeaderOffset + 30 + lNameLen + lExtraLen;
        const compSlice = zipBuf.slice(dataStart, dataStart + ent.compSize);
        const fileBytes = ent.method === 0 ? compSlice : zlib.inflateRawSync(compSlice);
        fs.mkdirSync(path.dirname(outPath), { recursive: true });
        fs.writeFileSync(outPath, fileBytes);
        writtenFiles++;
    }
    return writtenFiles;
}

function normalizeExtractedGitHubPluginDir(targetDir, spec, pluginSlug, sourceUrl) {
    // 1. Check nested manifest conventions (.antigravity-plugin/plugin.json, .gemini-plugin/plugin.json, .claude-plugin/plugin.json)
    const rootManifestPath = path.join(targetDir, "plugin.json");
    if (!fs.existsSync(rootManifestPath)) {
        for (const altRel of [
            path.join(".antigravity-plugin", "plugin.json"),
            path.join(".gemini-plugin", "plugin.json"),
            path.join(".claude-plugin", "plugin.json")
        ]) {
            const altFull = path.join(targetDir, altRel);
            if (fs.existsSync(altFull)) {
                fs.copyFileSync(altFull, rootManifestPath);
                break;
            }
        }
    }

    // 2. If root has a standalone `SKILL.md` (and no `skills/` dir yet), wrap it into `skills/<slug>/SKILL.md`
    let detectedDescription = "";
    let detectedTitle = spec.subPath ? path.posix.basename(spec.subPath) : spec.repo;
    const rootSkillMd = path.join(targetDir, "SKILL.md");
    if (fs.existsSync(rootSkillMd)) {
        const skillText = fs.readFileSync(rootSkillMd, "utf8");
        const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(skillText);
        if (fm) {
            const nm = /^name:\s*(.+)$/m.exec(fm[1]);
            const ds = /^description:\s*(.+)$/m.exec(fm[1]);
            if (nm) detectedTitle = nm[1].trim().replace(/^["']|["']$/g, "");
            if (ds) detectedDescription = ds[1].trim().replace(/^["']|["']$/g, "");
        }
        const skillDestDir = path.join(targetDir, "skills", pluginSlug);
        fs.mkdirSync(skillDestDir, { recursive: true });
        fs.copyFileSync(rootSkillMd, path.join(skillDestDir, "SKILL.md"));
        // Also copy helper subdirectories (`scripts/`, `references/`, `assets/`) if present alongside root SKILL.md
        for (const helperSub of ["scripts", "references", "assets", "docs", "templates"]) {
            const srcSub = path.join(targetDir, helperSub);
            if (fs.existsSync(srcSub) && fs.statSync(srcSub).isDirectory()) {
                fs.cpSync(srcSub, path.join(skillDestDir, helperSub), { recursive: true });
            }
        }
    }

    // 3. Normalize `.mcp.json` -> `mcp_config.json` if needed
    const dotMcp = path.join(targetDir, ".mcp.json");
    const mcpCfg = path.join(targetDir, "mcp_config.json");
    if (fs.existsSync(dotMcp) && !fs.existsSync(mcpCfg)) {
        fs.copyFileSync(dotMcp, mcpCfg);
    }

    // 4. Normalize root `AGENTS.md` -> `rules/AGENTS.md` if neither skills nor plugin.json existed
    const rootAgentsMd = path.join(targetDir, "AGENTS.md");
    const rulesAgentsMd = path.join(targetDir, "rules", "AGENTS.md");
    if (fs.existsSync(rootAgentsMd) && !fs.existsSync(rulesAgentsMd)) {
        fs.mkdirSync(path.dirname(rulesAgentsMd), { recursive: true });
        fs.copyFileSync(rootAgentsMd, rulesAgentsMd);
    }

    // 5. Extract fallback description from README.md if needed
    const readmePath = path.join(targetDir, "README.md");
    if (!detectedDescription && fs.existsSync(readmePath)) {
        const lines = fs.readFileSync(readmePath, "utf8").split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith("#") && !l.startsWith("!"));
        if (lines[0]) detectedDescription = lines[0].slice(0, 220);
    }

    // 6. Ensure valid `plugin.json` exists at root
    let manifest = {};
    if (fs.existsSync(rootManifestPath)) {
        try { manifest = JSON.parse(fs.readFileSync(rootManifestPath, "utf8")); } catch {}
    }
    manifest.name = manifest.name || pluginSlug;
    manifest.displayName = manifest.displayName || detectedTitle || pluginSlug;
    manifest.version = manifest.version || "1.0.0";
    manifest.description = manifest.description || detectedDescription || `Installed from GitHub (${spec.owner}/${spec.repo})`;
    manifest.author = manifest.author || { name: spec.owner };
    manifest.repository = manifest.repository || `https://github.com/${spec.owner}/${spec.repo}`;
    manifest.installedFrom = {
        type: "github",
        url: sourceUrl
    };

    if (fs.existsSync(mcpCfg) && !manifest.mcpServers) {
        manifest.mcpServers = "./mcp_config.json";
    }
    fs.writeFileSync(rootManifestPath, JSON.stringify(manifest, null, 2), "utf8");
    return manifest;
}

async function installPluginFromGitHubUrl(rawUrlInput, pluginsInstallRoot) {
    const spec = parseGitHubRepoSpec(rawUrlInput);
    const zipUrls = spec.directZipUrl
        ? [spec.directZipUrl]
        : (spec.branch
            ? [`https://codeload.github.com/${spec.owner}/${spec.repo}/zip/refs/heads/${spec.branch}`, `https://codeload.github.com/${spec.owner}/${spec.repo}/zip/${spec.branch}`]
            : [`https://codeload.github.com/${spec.owner}/${spec.repo}/zip/HEAD`, `https://codeload.github.com/${spec.owner}/${spec.repo}/zip/refs/heads/main`, `https://codeload.github.com/${spec.owner}/${spec.repo}/zip/refs/heads/master`]);

    let zipBuf = null;
    let lastErr = null;
    for (const u of zipUrls) {
        try {
            zipBuf = await downloadBufferWithProxy(u);
            if (zipBuf && zipBuf.length > 22) break;
        } catch (e) {
            lastErr = e;
        }
    }
    if (!zipBuf) {
        throw new Error(`Failed to download GitHub repository (${spec.owner}/${spec.repo}): ${lastErr ? lastErr.message : "Not found"}`);
    }

    const baseSlugSource = spec.subPath ? `${spec.repo}-${path.posix.basename(spec.subPath)}` : spec.repo;
    const pluginSlug = baseSlugSource.toLowerCase().replace(/[^a-z0-9_-]/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "") || `gh-plugin-${Date.now()}`;
    const targetDir = path.join(pluginsInstallRoot, pluginSlug);

    if (fs.existsSync(targetDir)) {
        fs.rmSync(targetDir, { recursive: true, force: true });
    }
    const count = extractZipToFolderWithStrip(zipBuf, targetDir, spec.subPath);
    if (count === 0) {
        fs.rmSync(targetDir, { recursive: true, force: true });
        throw new Error(spec.subPath ? `Subfolder "${spec.subPath}" was not found inside ${spec.owner}/${spec.repo}.` : "Repository archive was empty.");
    }

    const manifest = normalizeExtractedGitHubPluginDir(targetDir, spec, pluginSlug, String(rawUrlInput).trim());
    return {
        pluginId: pluginSlug,
        displayName: manifest.displayName || pluginSlug,
        description: manifest.description || "",
        targetDir,
        filesExtracted: count
    };
}

module.exports = {
    loadPlusSettings,
    savePlusSettings,
    getProxyEnvForLanguageServer,
    createProxiedRequest,
    downloadBufferWithProxy,
    testProxyConnectionLive,
    getOrderedApiKeysForModel,
    markApiKeyModelQuotaExhausted,
    recordOAuthSlotQuotaSummary,
    markOAuthSlotModelExhausted,
    findNextAvailableOAuthSlotForModel,
    getQuotaCooldownsOverview,
    clearAllQuotaCooldowns,
    subscribeTelemetrySse,
    tickStreamingTelemetry,
    recordRequestTelemetry,
    getTelemetrySnapshot,
    resetTelemetrySnapshot,
    installPluginFromGitHubUrl
};
