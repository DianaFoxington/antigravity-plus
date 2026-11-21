"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ensureGatewayForwarder = ensureGatewayForwarder;
exports.getBoundGatewayPort = getBoundGatewayPort;
exports.getActiveApiKey = getActiveApiKey;
exports.getCurrentAuthMode = getCurrentAuthMode;
exports.getActiveOAuthAppDataDir = getActiveOAuthAppDataDir;
exports.prepareAuthEnvironmentBeforeSpawn = prepareAuthEnvironmentBeforeSpawn;
exports.openOAuthUrlInChrome = openOAuthUrlInChrome;
exports.registerLsHotRestart = registerLsHotRestart;

const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const os = require("os");
const zlib = require("zlib");
const crypto = require("crypto");
const { StringDecoder } = require("string_decoder");
const { execFileSync, spawn } = require("child_process");
const {
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
} = require("./networkAndPlugins");
const {
    SUPPORTED_LANGUAGES,
    getLocalePackByCode,
    buildAppearanceLanguageAndI18nCode
} = require("./uiLocalization");
exports.getProxyEnvForLanguageServer = getProxyEnvForLanguageServer;

const CERT_PATH = path.join(os.homedir(), ".gemini", "cert.pem");
const KEY_PATH = path.join(os.homedir(), ".gemini", "key.pem");
const DEFAULT_PORT = 43199;
const INITIAL_SEED_API_KEY = "";

function derLen(len) {
    if (len < 0x80) return Buffer.from([len]);
    const bytes = [];
    let n = len;
    while (n > 0) { bytes.unshift(n & 0xff); n >>= 8; }
    return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function derTag(tag, contentBuf) {
    return Buffer.concat([Buffer.from([tag]), derLen(contentBuf.length), contentBuf]);
}
function derSeq(...items) { return derTag(0x30, Buffer.concat(items)); }
function derSet(...items) { return derTag(0x31, Buffer.concat(items)); }
function derOid(oidNums) {
    const body = [40 * oidNums[0] + oidNums[1]];
    for (let i = 2; i < oidNums.length; i++) {
        let v = oidNums[i];
        if (v === 0) { body.push(0); continue; }
        const enc = [];
        while (v > 0) { enc.unshift(v & 0x7f); v = Math.floor(v / 128); }
        for (let j = 0; j < enc.length - 1; j++) enc[j] |= 0x80;
        body.push(...enc);
    }
    return derTag(0x06, Buffer.from(body));
}
function derInt(bufOrNum) {
    let b = Buffer.isBuffer(bufOrNum) ? bufOrNum : Buffer.from([bufOrNum]);
    while (b.length > 1 && b[0] === 0 && (b[1] & 0x80) === 0) b = b.slice(1);
    if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0x00]), b]);
    return derTag(0x02, b);
}
function derBitString(buf) { return derTag(0x03, Buffer.concat([Buffer.from([0x00]), buf])); }
function derOctetString(buf) { return derTag(0x04, buf); }
function derUtf8(str) { return derTag(0x0c, Buffer.from(str, "utf8")); }
function derTime(date) {
    const pad = (n) => String(n).padStart(2, "0");
    if (date.getUTCFullYear() >= 2050) {
        const s = `${date.getUTCFullYear()}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
        return derTag(0x18, Buffer.from(s, "ascii"));
    }
    const yy = pad(date.getUTCFullYear() % 100);
    const s = `${yy}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
    return derTag(0x17, Buffer.from(s, "ascii"));
}

function generateSelfSignedLocalhostCert() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const spkiDer = publicKey.export({ type: "spki", format: "der" });
    const keyPem = privateKey.export({ type: "pkcs8", format: "pem" });
    const sigAlg = derSeq(derOid([1, 2, 840, 113549, 1, 1, 11]), Buffer.from([0x05, 0x00]));
    const name = derSeq(derSet(derSeq(derOid([2, 5, 4, 3]), derUtf8("localhost"))));
    const now = new Date(Date.now() - 86400 * 1000);
    const exp = new Date(Date.now() + 3650 * 86400 * 1000);
    const validity = derSeq(derTime(now), derTime(exp));

    const extBasicConstraints = derSeq(
        derOid([2, 5, 29, 19]),
        Buffer.from([0x01, 0x01, 0xff]),
        derOctetString(derSeq(Buffer.from([0x01, 0x01, 0xff])))
    );
    const extKeyUsage = derSeq(
        derOid([2, 5, 29, 15]),
        Buffer.from([0x01, 0x01, 0xff]),
        derOctetString(derTag(0x03, Buffer.from([0x02, 0xa4])))
    );
    const extEku = derSeq(
        derOid([2, 5, 29, 37]),
        derOctetString(derSeq(derOid([1, 3, 6, 1, 5, 5, 7, 3, 1])))
    );
    const sanContent = derSeq(
        derTag(0x82, Buffer.from("localhost", "ascii")),
        derTag(0x87, Buffer.from([127, 0, 0, 1])),
        derTag(0x87, Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
    );
    const extSan = derSeq(derOid([2, 5, 29, 17]), derOctetString(sanContent));
    const extensions = derTag(0xa3, derSeq(extBasicConstraints, extKeyUsage, extEku, extSan));
    const tbsCert = derSeq(derTag(0xa0, derInt(2)), derInt(crypto.randomBytes(16)), sigAlg, name, validity, name, spkiDer, extensions);
    const sig = crypto.sign("sha256", tbsCert, privateKey);
    const fullCertDer = derSeq(tbsCert, sigAlg, derBitString(sig));
    const b64 = fullCertDer.toString("base64").match(/.{1,64}/g).join("\n");
    const certPem = `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
    return { certPem, keyPem };
}

function ensureLocalTlsCertificates() {
    try {
        if (fs.existsSync(CERT_PATH) && fs.existsSync(KEY_PATH)) {
            const existingCert = fs.readFileSync(CERT_PATH, "utf8");
            const existingKey = fs.readFileSync(KEY_PATH, "utf8");
            if (existingCert.includes("BEGIN CERTIFICATE") && existingKey.includes("PRIVATE KEY")) {
                return { cert: Buffer.from(existingCert, "utf8"), key: Buffer.from(existingKey, "utf8") };
            }
        }
    } catch {}
    const { certPem, keyPem } = generateSelfSignedLocalhostCert();
    fs.mkdirSync(path.dirname(CERT_PATH), { recursive: true });
    fs.writeFileSync(CERT_PATH, certPem, { encoding: "utf8" });
    fs.writeFileSync(KEY_PATH, keyPem, { encoding: "utf8", mode: 0o600 });
    return { cert: Buffer.from(certPem, "utf8"), key: Buffer.from(keyPem, "utf8") };
}

function getAdminSettingsTargetPaths() {
    const home = os.homedir();
    if (process.platform === "win32") {
        const progData = process.env.PROGRAMDATA || "C:\\ProgramData";
        const appData = process.env.APPDATA || path.join(home, "AppData", "Roaming");
        return [
            path.join(progData, "Antigravity", "admin_settings.json"),
            path.join(appData, "Antigravity", "admin_settings.json")
        ];
    }
    if (process.platform === "darwin") {
        return [
            path.join(home, "Library", "Application Support", "Antigravity", "admin_settings.json"),
            "/Library/Application Support/Antigravity/admin_settings.json"
        ];
    }
    const xdgConfig = process.env.XDG_CONFIG_HOME || path.join(home, ".config");
    return [
        path.join(xdgConfig, "Antigravity", "admin_settings.json"),
        path.join(home, ".config", "antigravity", "admin_settings.json"),
        "/etc/antigravity/admin_settings.json"
    ];
}

const AGY_JSON_CONFIG_PATH = path.join(os.homedir(), ".gemini", "antigravity.json");
const AUTH_MODE_STATE_PATH = path.join(os.homedir(), ".gemini", "antigravity_auth_mode.json");
const OAUTH_PROFILES_DIR = path.join(os.homedir(), ".gemini", "oauth_profiles");
const LEGACY_KEYS_VAULT_PATH = path.join(os.homedir(), ".gemini", "antigravity_api_keys.json");

const PLUGINS_INSTALL_ROOT = path.join(os.homedir(), ".gemini", "config", "plugins");
const MARKETPLACE_CACHE_FILES = [
    {
        marketplace: "antigravity-plugins-official",
        groupTitle: "Official Google Plugins",
        groupDesc: "First-party skills, tools, and MCP integrations built by Google teams.",
        filePath: path.join(os.homedir(), ".gemini", "antigravity", "cache", "marketplaces", "antigravity-plugins-official", "marketplace.json")
    },
    {
        marketplace: "antigravity-plugins-partners",
        groupTitle: "Partner Ecosystem Plugins",
        groupDesc: "Verified developer tools, cloud, design, and productivity plugins.",
        filePath: path.join(os.homedir(), ".gemini", "antigravity", "cache", "marketplaces", "antigravity-plugins-partners", "marketplace.json")
    }
];

const DEFAULT_UNLOCKED_FLAGS = [
    "labs-autonomous-mode",
    "jetski-autonomous-mode",
    "labs-concierge-agent",
    "labs-inline-actions",
    "jetski-generative-ui",
    "enable-battle-mode",
    "enable-battle-contrib-variants",
    "enable-side-question-rework",
    "enable-auto-permission-preset",
    "enable-permissions-selector",
    "enable-conversation-scoped-permissions",
    "permission-v2",
    "cortex-snapshot-revert",
    "enable-thought-editing",
    "enable-thought-steering-from-selection",
    "enable-resume-conversations-from-restart",
    "enable-resource-manager",
    "context-window-selector",
    "enable-conversation-forking",
    "enable-fork-at-historical-step",
    "enable-fork-in-new-worktree",
    "enable-conversation-groups",
    "enable-conversation-search-v2",
    "enable-conversation-navigator",
    "enable-conversation-navigator-chapter-titles",
    "enable-conversation-selection-quoting",
    "enable-conversation-sharing-prototype",
    "enable-input-autocomplete",
    "enable-paste-text-as-snippet",
    "enable-text-transitions",
    "enable-sidebar-unread-dot",
    "enable-split-view",
    "enable-file-explorer-tab",
    "enable-file-viewer-keyboard-navigation",
    "enable-code-search-palette",
    "enable-bottom-terminal-panel",
    "enable-jetbox-terminal-v2",
    "enable-hub-builtin-browser",
    "enable-browser-subagent-v2",
    "enable-pdf-viewer",
    "enable-notebook-rendering",
    "markdown-table-v2",
    "configure-artifact-width",
    "enable-pane-selection-actions",
    "enable-aux-pane-redesign",
    "enable-git-vcs-ui",
    "enable-plugins",
    "enable-agent-plugins-spec",
    "jetski-unified-customizations-panel-enabled",
    "enable-plugin-sidebar-section",
    "enable-plugin-context-providers",
    "enable-plugin-themes",
    "enable-plugin-auth",
    "enable-mcp-plugin-auth",
    "enable-sidecar-pill-auto-open",
    "enable-plugin-card-auto-resume",
    "enable-new-themes",
    "enable-keybinding-customization",
    "enable-notifications-settings",
    "enable-context-menu-system",
    "enable-developer-mode",
    "enable-trajectory-debug-tools",
    "enable-settings-error-card",
    "enable-per-conversation-telemetry-toggle",
    "remote-control-setting-enabled",
    "enable-subagent-hub",
    "enable-teamwork-subagent",
    "convenient-multi-agent-coordination",
    "enable-generative-hooks",
    ...(process.platform !== "win32" ? ["enable-programmatic-tools"] : []),
    "enable-url-artifacts",
    "enable-owl-slash-command",
    "enable-compact-slash-command"
];

const EFFORT_LEVELS = [
    { suffix: "low", label: "Low", budget: 1024 },
    { suffix: "medium", label: "Medium", budget: 8192 },
    { suffix: "high", label: "High", budget: 24576 },
    { suffix: "max", label: "Max", budget: 32768 }
];

const EFFORT_BUDGET_MAP = {
    low: 1024,
    medium: 8192,
    high: 24576,
    max: 32768
};

const FAILOVER_GOOGLE_MODELS = [
    "gemini-4-hydrogen",
    "gemini-4-argon",
    "gemini-4-carbon"
];

let activePortPromise = null;
let boundGatewayPort = DEFAULT_PORT;
let _lsHotRestartCallback = null;
const patchedBundleCache = new Map();

function registerLsHotRestart(fn) {
    _lsHotRestartCallback = fn;
}

// ---------------------------------------------------------------------------
// Auth Mode Manager + Native OS Keyring Multi-Account OAuth Vault
// ---------------------------------------------------------------------------
const KEYRING_SERVICE_TARGET = "gemini:antigravity";

const WIN_CRED_CSHARP = `
using System;
using System.Runtime.InteropServices;
public class AgyWinCred {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }
    [DllImport("advapi32.dll", EntryPoint="CredReadW", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CredRead(string target, uint type, int reservedFlag, out IntPtr credentialPtr);
    [DllImport("advapi32.dll", EntryPoint="CredWriteW", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CredWrite([In] ref CREDENTIAL userCredential, [In] uint flags);
    [DllImport("advapi32.dll", EntryPoint="CredDeleteW", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CredDelete(string target, uint type, int flags);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern void CredFree([In] IntPtr cred);

    public static string ReadB64(string target) {
        IntPtr ptr;
        if (!CredRead(target, 1, 0, out ptr)) {
            if (!CredRead("LegacyGeneric:target=" + target, 1, 0, out ptr)) return "";
        }
        try {
            CREDENTIAL c = (CREDENTIAL)Marshal.PtrToStructure(ptr, typeof(CREDENTIAL));
            if (c.CredentialBlobSize == 0 || c.CredentialBlob == IntPtr.Zero) return "";
            byte[] bytes = new byte[c.CredentialBlobSize];
            Marshal.Copy(c.CredentialBlob, bytes, 0, (int)c.CredentialBlobSize);
            return Convert.ToBase64String(bytes);
        } finally {
            CredFree(ptr);
        }
    }
    public static bool WriteB64(string target, string user, string b64) {
        byte[] bytes = Convert.FromBase64String(b64);
        IntPtr blob = Marshal.AllocHGlobal(bytes.Length);
        try {
            Marshal.Copy(bytes, 0, blob, bytes.Length);
            CREDENTIAL c = new CREDENTIAL();
            c.Type = 1;
            c.TargetName = target;
            c.UserName = user;
            c.CredentialBlobSize = (uint)bytes.Length;
            c.CredentialBlob = blob;
            c.Persist = 2;
            return CredWrite(ref c, 0);
        } finally {
            Marshal.FreeHGlobal(blob);
        }
    }
    public static void DeleteTarget(string target) {
        CredDelete(target, 1, 0);
        CredDelete("LegacyGeneric:target=" + target, 1, 0);
    }
}
`;

const WIN_CRED_HELPER_DIR = path.join(os.homedir(), ".gemini", "agy-unlocker");
const WIN_CRED_EXE_PATH = path.join(WIN_CRED_HELPER_DIR, "agy-wincred.exe");

const WIN_CRED_CSHARP_EXE = `
using System;
using System.Runtime.InteropServices;
class Program {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CREDENTIAL {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }
    [DllImport("advapi32.dll", EntryPoint="CredReadW", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CredRead(string target, uint type, int reservedFlag, out IntPtr credentialPtr);
    [DllImport("advapi32.dll", EntryPoint="CredWriteW", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CredWrite([In] ref CREDENTIAL userCredential, [In] uint flags);
    [DllImport("advapi32.dll", EntryPoint="CredDeleteW", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CredDelete(string target, uint type, int flags);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern void CredFree([In] IntPtr cred);

    static int Main(string[] args) {
        if (args.Length < 2) return 1;
        string cmd = args[0];
        string target = args[1];
        if (cmd == "read") {
            IntPtr ptr;
            if (!CredRead(target, 1, 0, out ptr)) {
                if (!CredRead("LegacyGeneric:target=" + target, 1, 0, out ptr)) return 0;
            }
            try {
                CREDENTIAL c = (CREDENTIAL)Marshal.PtrToStructure(ptr, typeof(CREDENTIAL));
                if (c.CredentialBlobSize > 0 && c.CredentialBlob != IntPtr.Zero) {
                    byte[] bytes = new byte[c.CredentialBlobSize];
                    Marshal.Copy(c.CredentialBlob, bytes, 0, (int)c.CredentialBlobSize);
                    Console.Write(Convert.ToBase64String(bytes));
                }
            } finally {
                CredFree(ptr);
            }
            return 0;
        }
        if (cmd == "write" && args.Length >= 4) {
            byte[] bytes = Convert.FromBase64String(args[3]);
            IntPtr blob = Marshal.AllocHGlobal(bytes.Length);
            try {
                Marshal.Copy(bytes, 0, blob, bytes.Length);
                CREDENTIAL c = new CREDENTIAL();
                c.Type = 1;
                c.TargetName = target;
                c.UserName = args[2];
                c.CredentialBlobSize = (uint)bytes.Length;
                c.CredentialBlob = blob;
                c.Persist = 2;
                return CredWrite(ref c, 0) ? 0 : 2;
            } finally {
                Marshal.FreeHGlobal(blob);
            }
        }
        if (cmd == "delete") {
            CredDelete(target, 1, 0);
            CredDelete("LegacyGeneric:target=" + target, 1, 0);
            return 0;
        }
        return 1;
    }
}
`;

let _winCredHelperReady = null;
function ensureFastWinCredExe() {
    if (process.platform !== "win32") return null;
    if (_winCredHelperReady && fs.existsSync(WIN_CRED_EXE_PATH)) return WIN_CRED_EXE_PATH;
    if (fs.existsSync(WIN_CRED_EXE_PATH)) {
        _winCredHelperReady = true;
        return WIN_CRED_EXE_PATH;
    }
    try {
        const winDir = process.env.WINDIR || "C:\\Windows";
        const cscCandidates = [
            path.join(winDir, "Microsoft.NET", "Framework64", "v4.0.30319", "csc.exe"),
            path.join(winDir, "Microsoft.NET", "Framework", "v4.0.30319", "csc.exe")
        ];
        const csc = cscCandidates.find(p => fs.existsSync(p));
        if (!csc) return null;
        fs.mkdirSync(WIN_CRED_HELPER_DIR, { recursive: true });
        const csTmp = path.join(WIN_CRED_HELPER_DIR, `agy-wincred-${process.pid}.cs`);
        fs.writeFileSync(csTmp, WIN_CRED_CSHARP_EXE, "utf8");
        try {
            execFileSync(csc, ["/nologo", "/optimize+", `/out:${WIN_CRED_EXE_PATH}`, csTmp], { stdio: "ignore" });
        } finally {
            try { fs.unlinkSync(csTmp); } catch {}
        }
        if (fs.existsSync(WIN_CRED_EXE_PATH)) {
            _winCredHelperReady = true;
            return WIN_CRED_EXE_PATH;
        }
    } catch {}
    return null;
}

let _keyringCacheVal = null;
let _keyringCacheTs = 0;

function readOsKeyringOAuthBlob(bypassCache = false) {
    if (!bypassCache && _keyringCacheVal !== null && Date.now() - _keyringCacheTs < 3000) {
        return _keyringCacheVal;
    }
    try {
        let out = "";
        if (process.platform === "win32") {
            const fastExe = ensureFastWinCredExe();
            if (fastExe) {
                const b64 = execFileSync(fastExe, ["read", KEYRING_SERVICE_TARGET], {
                    encoding: "utf8",
                    stdio: ["ignore", "pipe", "ignore"]
                }).trim();
                out = b64 ? Buffer.from(b64, "base64").toString("utf8") : "";
            } else {
                const ps = `Add-Type -TypeDefinition @'\n${WIN_CRED_CSHARP}\n'@; [AgyWinCred]::ReadB64('${KEYRING_SERVICE_TARGET}')`;
                const b64 = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", ps], {
                    encoding: "utf8",
                    stdio: ["ignore", "pipe", "ignore"]
                }).trim();
                out = b64 ? Buffer.from(b64, "base64").toString("utf8") : "";
            }
        } else if (process.platform === "darwin") {
            out = execFileSync("security", ["find-generic-password", "-s", KEYRING_SERVICE_TARGET, "-w"], {
                encoding: "utf8",
                stdio: ["ignore", "pipe", "ignore"]
            }).trim();
        } else {
            out = execFileSync("secret-tool", ["lookup", "service", KEYRING_SERVICE_TARGET], {
                encoding: "utf8",
                stdio: ["ignore", "pipe", "ignore"]
            }).trim();
        }
        _keyringCacheVal = out;
        _keyringCacheTs = Date.now();
        return out;
    } catch {
        return "";
    }
}

function writeOsKeyringOAuthBlob(rawJsonStr) {
    if (!rawJsonStr) return false;
    if (_keyringCacheVal === rawJsonStr && Date.now() - _keyringCacheTs < 10000) {
        return true;
    }
    try {
        if (process.platform === "win32") {
            const b64 = Buffer.from(rawJsonStr, "utf8").toString("base64");
            const fastExe = ensureFastWinCredExe();
            if (fastExe) {
                execFileSync(fastExe, ["write", KEYRING_SERVICE_TARGET, "antigravity", b64], { stdio: "ignore" });
            } else {
                const ps = `Add-Type -TypeDefinition @'\n${WIN_CRED_CSHARP}\n'@; [AgyWinCred]::WriteB64('${KEYRING_SERVICE_TARGET}', 'antigravity', '${b64}') | Out-Null`;
                execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", ps], { stdio: "ignore" });
            }
        } else if (process.platform === "darwin") {
            execFileSync("security", ["add-generic-password", "-U", "-s", KEYRING_SERVICE_TARGET, "-a", "antigravity", "-w", rawJsonStr], { stdio: "ignore" });
        } else {
            execFileSync("secret-tool", ["store", "--label=Antigravity OAuth", "service", KEYRING_SERVICE_TARGET, "username", "antigravity"], {
                input: rawJsonStr,
                encoding: "utf8",
                stdio: ["pipe", "ignore", "ignore"]
            });
        }
        _keyringCacheVal = rawJsonStr;
        _keyringCacheTs = Date.now();
        return true;
    } catch {
        return false;
    }
}

function clearOsKeyringOAuthBlob() {
    _keyringCacheVal = "";
    _keyringCacheTs = Date.now();
    try {
        if (process.platform === "win32") {
            const fastExe = ensureFastWinCredExe();
            if (fastExe) {
                execFileSync(fastExe, ["delete", KEYRING_SERVICE_TARGET], { stdio: "ignore" });
            } else {
                const ps = `Add-Type -TypeDefinition @'\n${WIN_CRED_CSHARP}\n'@; [AgyWinCred]::DeleteTarget('${KEYRING_SERVICE_TARGET}')`;
                execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", ps], { stdio: "ignore" });
            }
        } else if (process.platform === "darwin") {
            execFileSync("security", ["delete-generic-password", "-s", KEYRING_SERVICE_TARGET], { stdio: "ignore" });
        } else {
            execFileSync("secret-tool", ["clear", "service", KEYRING_SERVICE_TARGET], { stdio: "ignore" });
        }
    } catch {}
}

function focusMainAppWindow() {
    try {
        const { BrowserWindow } = require("electron");
        const wins = BrowserWindow.getAllWindows();
        if (wins && wins.length > 0) {
            const w = wins[0];
            if (w.isMinimized()) w.restore();
            w.show();
            w.focus();
        }
    } catch {}
}

function getSlotVaultCredPath(slotId) {
    const cleanId = String(slotId || "").replace(/[^a-zA-Z0-9_-]/g, "");
    return path.join(OAUTH_PROFILES_DIR, `${cleanId}.cred.json`);
}

function readSlotVaultCred(slotId) {
    try {
        const p = getSlotVaultCredPath(slotId);
        if (fs.existsSync(p)) {
            return fs.readFileSync(p, "utf8");
        }
    } catch {}
    return "";
}

function saveSlotVaultCred(slotId, rawBlobStr) {
    if (!slotId || !rawBlobStr) return;
    try {
        fs.mkdirSync(OAUTH_PROFILES_DIR, { recursive: true });
        fs.writeFileSync(getSlotVaultCredPath(slotId), rawBlobStr, { encoding: "utf8", mode: 0o600 });
    } catch {}
}

function snapshotCurrentKeyringToActiveSlot(st) {
    if (!st || !st.activeSlotId) return;
    const activeSlot = (st.slots || []).find(s => s.id === st.activeSlotId);
    if (!activeSlot) return;
    const liveBlob = readOsKeyringOAuthBlob();
    if (!liveBlob) return;
    try {
        const parsed = JSON.parse(liveBlob);
        const blobEmail = String(parsed?.id_token_email || "").trim().toLowerCase();
        if (!activeSlot.email || !blobEmail || activeSlot.email.toLowerCase() === blobEmail) {
            saveSlotVaultCred(activeSlot.id, liveBlob);
            if (blobEmail && !activeSlot.email) {
                activeSlot.email = blobEmail;
                if (!activeSlot.name || /^Google Account/i.test(activeSlot.label || "")) {
                    activeSlot.label = blobEmail.split("@")[0];
                }
                saveAuthModeState(st);
            }
        }
    } catch {}
}

function openOAuthUrlInChrome(rawUrl) {
    let targetUrl = String(rawUrl || "").trim();
    if (!targetUrl) return false;

    // Force Google Account / Email selector (`select_account`) so Chrome always asks which Google account to use
    try {
        const u = new URL(targetUrl);
        if (u.hostname.includes("accounts.google.com")) {
            const curPrompt = u.searchParams.get("prompt") || "";
            if (!curPrompt.includes("select_account")) {
                u.searchParams.set("prompt", curPrompt ? `select_account ${curPrompt}` : "select_account consent");
                targetUrl = u.toString();
            }
        }
    } catch {}

    // Prefer launching Google Chrome directly if installed on Windows / macOS / Linux
    try {
        if (process.platform === "win32") {
            const chromeCandidates = [
                path.join(process.env.PROGRAMFILES || "C:\\Program Files", "Google", "Chrome", "Application", "chrome.exe"),
                path.join(process.env["PROGRAMFILES(X86)"] || "C:\\Program Files (x86)", "Google", "Chrome", "Application", "chrome.exe"),
                path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local"), "Google", "Chrome", "Application", "chrome.exe")
            ];
            const chromeExe = chromeCandidates.find(p => fs.existsSync(p));
            if (chromeExe) {
                const child = spawn(chromeExe, [targetUrl], { detached: true, stdio: "ignore" });
                child.unref();
                return true;
            }
        } else if (process.platform === "darwin") {
            if (fs.existsSync("/Applications/Google Chrome.app")) {
                const child = spawn("open", ["-a", "Google Chrome", targetUrl], { detached: true, stdio: "ignore" });
                child.unref();
                return true;
            }
        } else {
            for (const bin of ["google-chrome", "google-chrome-stable", "chromium-browser", "chromium"]) {
                try {
                    execFileSync("which", [bin], { stdio: "ignore" });
                    const child = spawn(bin, [targetUrl], { detached: true, stdio: "ignore" });
                    child.unref();
                    return true;
                } catch {}
            }
        }
    } catch {}

    try {
        const { shell } = require("electron");
        void shell.openExternal(targetUrl);
        return true;
    } catch {
        return false;
    }
}

function loadAuthModeState() {
    try {
        if (fs.existsSync(AUTH_MODE_STATE_PATH)) {
            const parsed = JSON.parse(fs.readFileSync(AUTH_MODE_STATE_PATH, "utf8"));
            if (parsed && (parsed.mode === "apikey" || parsed.mode === "google_oauth")) {
                parsed.slots = Array.isArray(parsed.slots) ? parsed.slots : [];
                if (parsed.slots.length === 0) {
                    parsed.activeSlotId = "";
                } else if (!parsed.slots.some(s => s.id === parsed.activeSlotId)) {
                    parsed.activeSlotId = parsed.slots[0].id;
                }
                // One-time vault sync if active slot has no .cred.json yet while OS keyring holds its token
                if (parsed.slots.length > 0) {
                    const act = parsed.slots.find(s => s.id === parsed.activeSlotId) || parsed.slots[0];
                    if (act && !readSlotVaultCred(act.id)) {
                        const liveBlob = readOsKeyringOAuthBlob();
                        if (liveBlob) {
                            try {
                                const jb = JSON.parse(liveBlob);
                                const bEmail = String(jb?.id_token_email || "").trim();
                                if (!act.email || !bEmail || act.email.toLowerCase() === bEmail.toLowerCase()) {
                                    saveSlotVaultCred(act.id, liveBlob);
                                    if (bEmail && !act.email) act.email = bEmail;
                                }
                            } catch {}
                        }
                    }
                }
                return parsed;
            }
        }
    } catch {}
    const initial = {
        mode: "apikey",
        activeSlotId: "",
        slots: []
    };
    saveAuthModeState(initial);
    return initial;
}

function saveAuthModeState(state) {
    try {
        fs.mkdirSync(path.dirname(AUTH_MODE_STATE_PATH), { recursive: true });
        fs.writeFileSync(AUTH_MODE_STATE_PATH, JSON.stringify(state, null, 2), "utf8");
    } catch {}
}

function getCurrentAuthMode() {
    return loadAuthModeState().mode;
}

function getActiveOAuthAppDataDir(defaultDirName) {
    // Keep conversations & plugins unified in defaultDirName while isolating OAuth credentials via OS Keyring Vault!
    return defaultDirName;
}

function deleteOAuthSlotCredentials(slotId, wasActiveInKeyring = false) {
    try {
        const vp = getSlotVaultCredPath(slotId);
        if (fs.existsSync(vp)) fs.unlinkSync(vp);
    } catch {}
    if (wasActiveInKeyring) {
        clearOsKeyringOAuthBlob();
    }
}

function removeAdminSettingsFilesForOAuthMode() {
    for (const p of getAdminSettingsTargetPaths()) {
        try {
            if (fs.existsSync(p)) {
                try {
                    fs.unlinkSync(p);
                } catch {
                    // Fallback if system folder ACL prevents delete: overwrite with empty JSON so gateway is disabled
                    fs.writeFileSync(p, "{}", "utf8");
                }
            }
        } catch {}
    }
}

async function prepareAuthEnvironmentBeforeSpawn(gwPort) {
    const st = loadAuthModeState();
    if (st.mode === "google_oauth") {
        removeAdminSettingsFilesForOAuthMode();
        if (st.activeSlotId) {
            const vaulted = readSlotVaultCred(st.activeSlotId);
            if (vaulted) {
                writeOsKeyringOAuthBlob(vaulted);
            }
        }
    } else {
        await syncAdminSettingsFiles(gwPort || boundGatewayPort, true);
    }
}

async function applyAuthModeAndRestartLs(targetMode, targetSlotId = null) {
    const st = loadAuthModeState();
    // Save current active OAuth keyring token into its slot vault before switching
    if (st.mode === "google_oauth" && st.activeSlotId) {
        snapshotCurrentKeyringToActiveSlot(st);
    }

    st.mode = targetMode;
    if (targetSlotId) {
        st.activeSlotId = targetSlotId;
    }
    saveAuthModeState(st);

    if (targetMode === "google_oauth") {
        removeAdminSettingsFilesForOAuthMode();
        const vaulted = st.activeSlotId ? readSlotVaultCred(st.activeSlotId) : "";
        if (vaulted) {
            writeOsKeyringOAuthBlob(vaulted);
        } else {
            clearOsKeyringOAuthBlob();
        }
    } else {
        await syncAdminSettingsFiles(boundGatewayPort, true);
    }

    let lsInfo = { restarted: false, samePort: false };
    if (_lsHotRestartCallback) {
        try {
            lsInfo = (await _lsHotRestartCallback()) || lsInfo;
        } catch (err) {
            console.error("[GatewayForwarder] Hot restart failed:", err);
        }
    }
    return { st, lsInfo };
}

let _preLoginSnapshot = null;

async function handleAuthModeRequest(urlPath, req, res, rawBodyBuf) {
    const corsHeaders = {
        "Content-Type": "application/json; charset=UTF-8",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type"
    };
    if (req.method === "OPTIONS") {
        res.writeHead(204, corsHeaders);
        return res.end();
    }

    const formatState = (st) => ({
        mode: st.mode,
        activeSlotId: st.activeSlotId,
        slots: st.slots.map(s => ({
            ...s,
            hasSavedCreds: Boolean(readSlotVaultCred(s.id))
        }))
    });

    if (urlPath === "/__agy_auth/status") {
        res.writeHead(200, corsHeaders);
        return res.end(JSON.stringify(formatState(loadAuthModeState())));
    }

    let payload = {};
    try { payload = JSON.parse(rawBodyBuf.toString("utf8") || "{}"); } catch {}

    if (urlPath === "/__agy_auth/switch_mode" && req.method === "POST") {
        try {
            const nextMode = payload.mode === "google_oauth" ? "google_oauth" : "apikey";
            const slotId = payload.slotId ? String(payload.slotId).trim() : null;
            const { st, lsInfo } = await applyAuthModeAndRestartLs(nextMode, slotId);
            res.writeHead(200, corsHeaders);
            return res.end(JSON.stringify({ success: true, samePort: !!lsInfo.samePort, ...formatState(st) }));
        } catch (err) {
            res.writeHead(500, corsHeaders);
            return res.end(JSON.stringify({ success: false, message: err.message }));
        }
    }

    if (urlPath === "/__agy_auth/add_oauth_slot" && req.method === "POST") {
        try {
            const st = loadAuthModeState();
            const wasAlreadyOAuth = st.mode === "google_oauth";
            snapshotCurrentKeyringToActiveSlot(st);
            _preLoginSnapshot = {
                prevMode: st.mode,
                prevActiveSlotId: st.activeSlotId,
                newSlotId: `acc-${Date.now()}`
            };

            const newId = _preLoginSnapshot.newSlotId;
            const label = String(payload.label || "").trim() || `Google Account ${st.slots.length + 1}`;
            st.slots.push({ id: newId, label, email: "", name: "" });
            st.activeSlotId = newId;
            st.mode = "google_oauth";
            saveAuthModeState(st);

            removeAdminSettingsFilesForOAuthMode();
            clearOsKeyringOAuthBlob();

            let lsInfo = { samePort: true };
            // Only hot-restart LS if transitioning from apikey -> google_oauth!
            // If already in google_oauth, authLogout() RPC clears LS in-memory auth in 10ms without restarting LS!
            if (!wasAlreadyOAuth && _lsHotRestartCallback) {
                try { lsInfo = (await _lsHotRestartCallback()) || lsInfo; } catch {}
            }
            res.writeHead(200, corsHeaders);
            return res.end(JSON.stringify({
                success: true,
                newSlotId: newId,
                alreadyInOAuthMode: wasAlreadyOAuth,
                samePort: !!lsInfo.samePort,
                ...formatState(st)
            }));
        } catch (err) {
            res.writeHead(500, corsHeaders);
            return res.end(JSON.stringify({ success: false, message: err.message }));
        }
    }

    if (urlPath === "/__agy_auth/finalize_oauth_login" && req.method === "POST") {
        try {
            const st = loadAuthModeState();
            const liveBlob = readOsKeyringOAuthBlob(true);
            let blobEmail = String(payload.email || "").trim();
            const uName = String(payload.name || "").trim();
            if (liveBlob) {
                try {
                    const jb = JSON.parse(liveBlob);
                    if (jb?.id_token_email) blobEmail = String(jb.id_token_email).trim();
                } catch {}
            }

            let targetSlot = st.slots.find(s => s.id === st.activeSlotId);
            // Deduplicate if user signed into an email that already had a slot
            if (blobEmail) {
                const existingSameEmail = st.slots.find(
                    s => s.id !== st.activeSlotId && s.email && s.email.toLowerCase() === blobEmail.toLowerCase()
                );
                if (existingSameEmail) {
                    st.slots = st.slots.filter(s => s.id !== st.activeSlotId);
                    st.activeSlotId = existingSameEmail.id;
                    targetSlot = existingSameEmail;
                }
            }

            if (targetSlot) {
                if (liveBlob) saveSlotVaultCred(targetSlot.id, liveBlob);
                if (blobEmail) targetSlot.email = blobEmail;
                if (uName && uName !== "Google Gemini") {
                    targetSlot.name = uName;
                    targetSlot.label = uName;
                } else if (blobEmail && /^Google Account/i.test(targetSlot.label || "")) {
                    targetSlot.label = blobEmail.split("@")[0];
                }
            }
            _preLoginSnapshot = null;
            saveAuthModeState(st);
            focusMainAppWindow();
            res.writeHead(200, corsHeaders);
            return res.end(JSON.stringify({ success: true, email: blobEmail, ...formatState(st) }));
        } catch (err) {
            res.writeHead(500, corsHeaders);
            return res.end(JSON.stringify({ success: false, message: err.message }));
        }
    }

    if (urlPath === "/__agy_auth/cancel_oauth_login" && req.method === "POST") {
        try {
            const st = loadAuthModeState();
            if (_preLoginSnapshot) {
                const { prevMode, prevActiveSlotId, newSlotId } = _preLoginSnapshot;
                _preLoginSnapshot = null;
                if (newSlotId && !readSlotVaultCred(newSlotId)) {
                    st.slots = st.slots.filter(s => s.id !== newSlotId);
                }
                st.mode = st.slots.length === 0 ? "apikey" : prevMode;
                st.activeSlotId = st.slots.some(s => s.id === prevActiveSlotId)
                    ? prevActiveSlotId
                    : (st.slots[0]?.id || "");
                saveAuthModeState(st);
                await applyAuthModeAndRestartLs(st.mode, st.activeSlotId || null);
            }
            res.writeHead(200, corsHeaders);
            return res.end(JSON.stringify({ success: true, ...formatState(loadAuthModeState()) }));
        } catch (err) {
            res.writeHead(500, corsHeaders);
            return res.end(JSON.stringify({ success: false, message: err.message }));
        }
    }

    if (urlPath === "/__agy_auth/delete_oauth_slot" && req.method === "POST") {
        try {
            const slotId = String(payload.slotId || "").trim();
            const st = loadAuthModeState();
            const wasActive = st.activeSlotId === slotId;
            st.slots = st.slots.filter(s => s.id !== slotId);
            deleteOAuthSlotCredentials(slotId, wasActive);

            if (st.slots.length === 0) {
                st.activeSlotId = "";
                const wasGoogleMode = st.mode === "google_oauth";
                if (wasGoogleMode) {
                    st.mode = "apikey";
                }
                saveAuthModeState(st);
                if (wasGoogleMode) {
                    await syncAdminSettingsFiles(boundGatewayPort, true);
                    if (_lsHotRestartCallback) {
                        try { await _lsHotRestartCallback(); } catch {}
                    }
                }
                res.writeHead(200, corsHeaders);
                return res.end(JSON.stringify({ success: true, switchedToApiKey: wasGoogleMode, ...formatState(st) }));
            }

            if (wasActive) {
                st.activeSlotId = st.slots[0].id;
                const nextVaulted = readSlotVaultCred(st.activeSlotId);
                if (nextVaulted) writeOsKeyringOAuthBlob(nextVaulted);
            }
            saveAuthModeState(st);

            if (wasActive && st.mode === "google_oauth" && _lsHotRestartCallback) {
                try { await _lsHotRestartCallback(); } catch {}
            }
            res.writeHead(200, corsHeaders);
            return res.end(JSON.stringify({ success: true, ...formatState(st) }));
        } catch (err) {
            res.writeHead(500, corsHeaders);
            return res.end(JSON.stringify({ success: false, message: err.message }));
        }
    }

    if (urlPath === "/__agy_auth/record_email" && req.method === "POST") {
        const email = String(payload.email || "").trim();
        const name = String(payload.name || "").trim();
        const st = loadAuthModeState();
        if (st.mode === "google_oauth" && email && email !== "gemini@google.com") {
            const slot = st.slots.find(s => s.id === st.activeSlotId);
            if (slot && (slot.email !== email || slot.name !== name)) {
                slot.email = email;
                if (name && name !== "Google Gemini") {
                    slot.name = name;
                    if (/^Google Account/i.test(slot.label || "")) {
                        slot.label = name;
                    }
                } else if (/^Google Account/i.test(slot.label || "")) {
                    slot.label = email.split("@")[0];
                }
                saveAuthModeState(st);
            }
        }
        res.writeHead(200, corsHeaders);
        return res.end(JSON.stringify({ ok: true, ...formatState(st) }));
    }

    if (urlPath === "/__agy_auth/report_oauth_quota" && req.method === "POST") {
        const st = loadAuthModeState();
        if (st.mode === "google_oauth" && st.activeSlotId && Array.isArray(payload.groups)) {
            recordOAuthSlotQuotaSummary(st.activeSlotId, payload.groups);
        }
        res.writeHead(200, corsHeaders);
        return res.end(JSON.stringify({ ok: true }));
    }

    if (urlPath === "/__agy_auth/auto_rotate_for_model" && req.method === "POST") {
        try {
            const st = loadAuthModeState();
            if (st.mode !== "google_oauth") {
                res.writeHead(200, corsHeaders);
                return res.end(JSON.stringify({ rotated: false }));
            }
            const modelHint = String(payload.model || "").trim();
            const exhaustedError = Boolean(payload.exhaustedError);
            if (exhaustedError && st.activeSlotId) {
                markOAuthSlotModelExhausted(st.activeSlotId, modelHint || "all");
            }
            const formatted = formatState(st);
            const nextSlot = findNextAvailableOAuthSlotForModel(
                formatted.slots,
                st.activeSlotId,
                modelHint,
                exhaustedError
            );
            if (!nextSlot || nextSlot.id === st.activeSlotId) {
                res.writeHead(200, corsHeaders);
                return res.end(JSON.stringify({ rotated: false }));
            }
            const { st: newSt, lsInfo } = await applyAuthModeAndRestartLs("google_oauth", nextSlot.id);
            res.writeHead(200, corsHeaders);
            return res.end(JSON.stringify({
                rotated: true,
                samePort: !!lsInfo.samePort,
                newAccountLabel: nextSlot.email || nextSlot.name || nextSlot.label,
                ...formatState(newSt)
            }));
        } catch (err) {
            res.writeHead(500, corsHeaders);
            return res.end(JSON.stringify({ rotated: false, error: err.message }));
        }
    }

    res.writeHead(404, corsHeaders);
    res.end(JSON.stringify({ error: "Not found" }));
}

// Route table populated from ~/.gemini/antigravity.json: gatewayBaseModelId -> routeDescriptor
const modelRouteTable = new Map();
// Dynamic context window limits: gatewayModelId / baseModelId -> contextTokens
const dynamicContextLimits = {};

const modelUsageEvents = new Map();
const modelTotalRequests = new Map();

function getBoundGatewayPort() {
    return boundGatewayPort;
}

// ---------------------------------------------------------------------------
// JSONC Parser & ~/.gemini/antigravity.json Configuration Manager
// ---------------------------------------------------------------------------
function stripJsonCommentsAndTrailingCommas(rawText) {
    // Pass 1: Strip // and /* */ comments while preserving "..." JSON string literals verbatim
    let noComments = "";
    let inStr = false;
    let i = 0;
    const n = rawText.length;

    while (i < n) {
        const ch = rawText[i];
        const next = i + 1 < n ? rawText[i + 1] : "";
        if (inStr) {
            noComments += ch;
            if (ch === "\\" && i + 1 < n) {
                noComments += rawText[i + 1];
                i += 2;
                continue;
            }
            if (ch === '"') inStr = false;
            i++;
            continue;
        }
        if (ch === '"') {
            inStr = true;
            noComments += ch;
            i++;
            continue;
        }
        if (ch === "/" && next === "/") {
            i += 2;
            while (i < n && rawText[i] !== "\n") i++;
            continue;
        }
        if (ch === "/" && next === "*") {
            i += 2;
            while (i + 1 < n && !(rawText[i] === "*" && rawText[i + 1] === "/")) i++;
            i = (i + 1 < n) ? i + 2 : n;
            continue;
        }
        noComments += ch;
        i++;
    }

    // Pass 2: Strip trailing commas before } or ] ONLY outside "..." string literals
    let out = "";
    inStr = false;
    i = 0;
    const m = noComments.length;
    while (i < m) {
        const ch = noComments[i];
        if (inStr) {
            out += ch;
            if (ch === "\\" && i + 1 < m) {
                out += noComments[i + 1];
                i += 2;
                continue;
            }
            if (ch === '"') inStr = false;
            i++;
            continue;
        }
        if (ch === '"') {
            inStr = true;
            out += ch;
            i++;
            continue;
        }
        if (ch === ",") {
            let look = i + 1;
            while (look < m && /\s/.test(noComments[look])) look++;
            if (look < m && (noComments[look] === "}" || noComments[look] === "]")) {
                i++;
                continue;
            }
        }
        out += ch;
        i++;
    }
    return out;
}

function parseJsonc(rawText) {
    return JSON.parse(stripJsonCommentsAndTrailingCommas(String(rawText || "{}")));
}

function buildDefaultAgyConfig() {
    let seedGoogleKey = (process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || INITIAL_SEED_API_KEY).trim();
    try {
        if (fs.existsSync(LEGACY_KEYS_VAULT_PATH)) {
            const v = JSON.parse(fs.readFileSync(LEGACY_KEYS_VAULT_PATH, "utf8"));
            if (v && Array.isArray(v.keys)) {
                const act = v.keys.find(k => k.active) || v.keys[0];
                seedGoogleKey = act ? String(act.key || "").trim() : "";
            }
        }
    } catch {}

    return {
        "provider": {
            "google": {
                "name": "Google Gemini",
                "npm": "@ai-sdk/google",
                "options": {
                    "baseURL": "https://generativelanguage.googleapis.com/v1beta",
                    "apiKey": seedGoogleKey
                },
                "models": {
                    "gemini-4-carbon": {
                        "name": "Gemini 4 Carbon",
                        "limit": { "context": 1048576, "output": 32768 },
                        "attachment": true,
                        "reasoning": true,
                        "tool_call": true,
                        "temperature": true,
                        "modalities": { "input": ["text", "image", "video"], "output": ["text"] }
                    },
                    "gemini-4-argon": {
                        "name": "Gemini 4 Argon",
                        "limit": { "context": 1048576, "output": 32768 },
                        "attachment": true,
                        "reasoning": true,
                        "tool_call": true,
                        "temperature": true,
                        "modalities": { "input": ["text", "image", "video"], "output": ["text"] }
                    },
                    "gemini-4-hydrogen": {
                        "name": "Gemini 4 Hydrogen",
                        "limit": { "context": 1048576, "output": 65536 },
                        "attachment": true,
                        "reasoning": true,
                        "tool_call": true,
                        "temperature": true,
                        "modalities": { "input": ["text", "image", "video"], "output": ["text"] }
                    },
                    "gemma-4-31b-it": {
                        "name": "Gemma 4 31B IT",
                        "limit": { "context": 262144, "output": 32768 },
                        "attachment": true,
                        "reasoning": true,
                        "tool_call": true,
                        "temperature": true,
                        "modalities": { "input": ["text", "image", "video"], "output": ["text"] }
                    },
                    "gemma-4-26b-a4b-it": {
                        "name": "Gemma 4 26B A4B IT",
                        "limit": { "context": 262144, "output": 32768 },
                        "attachment": true,
                        "reasoning": true,
                        "tool_call": true,
                        "temperature": true,
                        "modalities": { "input": ["text", "image", "video"], "output": ["text"] }
                    }
                }
            }
        }
    };
}

function ensureAgyConfigFile() {
    if (!fs.existsSync(AGY_JSON_CONFIG_PATH)) {
        const def = buildDefaultAgyConfig();
        fs.mkdirSync(path.dirname(AGY_JSON_CONFIG_PATH), { recursive: true });
        fs.writeFileSync(AGY_JSON_CONFIG_PATH, JSON.stringify(def, null, 2), "utf8");
    }
}

function readRawAgyConfigText() {
    ensureAgyConfigFile();
    return fs.readFileSync(AGY_JSON_CONFIG_PATH, "utf8");
}

function loadParsedAgyConfig() {
    try {
        const raw = readRawAgyConfigText();
        const parsed = parseJsonc(raw);
        if (parsed && typeof parsed === "object") {
            parsed.provider = (parsed.provider && typeof parsed.provider === "object") ? parsed.provider : {};
            return parsed;
        }
    } catch (err) {
        console.warn("[GatewayForwarder] Failed parsing antigravity.json:", err.message);
    }
    return buildDefaultAgyConfig();
}

function saveRawAgyConfigText(rawText) {
    const parsed = parseJsonc(rawText);
    if (!parsed || typeof parsed !== "object") {
        throw new Error("Root of config must be a JSON object.");
    }
    if (parsed.provider !== undefined && (typeof parsed.provider !== "object" || Array.isArray(parsed.provider))) {
        throw new Error('"provider" must be a JSON object mapping provider IDs to provider configs.');
    }
    fs.mkdirSync(path.dirname(AGY_JSON_CONFIG_PATH), { recursive: true });
    fs.writeFileSync(AGY_JSON_CONFIG_PATH, rawText, "utf8");
    return parsed;
}

function detectProviderProtocol(providerId, provCfg) {
    const npmPkg = String(provCfg?.npm || "").toLowerCase();
    const baseUrl = String(provCfg?.options?.baseURL || "").toLowerCase();
    const pid = String(providerId || "").toLowerCase();
    if (
        npmPkg.includes("anthropic") ||
        baseUrl.includes("api.anthropic.com") ||
        baseUrl.endsWith("/messages") ||
        (pid === "anthropic" && !npmPkg.includes("openai"))
    ) {
        return "anthropic-messages";
    }
    if (
        npmPkg.includes("azure") ||
        baseUrl.includes(".openai.azure.com")
    ) {
        return "azure-openai";
    }
    if (
        npmPkg.includes("google") ||
        baseUrl.includes("generativelanguage.googleapis.com") ||
        (pid === "google" && !npmPkg.includes("openai") && !npmPkg.includes("anthropic"))
    ) {
        return "google-genai";
    }
    return "openai-compatible";
}

function sanitizeGatewayModelBaseId(providerId, rawModelKey, protocol) {
    const cleanModel = String(rawModelKey || "").trim().replace(/[^a-zA-Z0-9._-]/g, "--");
    if (protocol === "google-genai" && providerId.toLowerCase() === "google") {
        return cleanModel;
    }
    const cleanProv = String(providerId || "custom").trim().replace(/[^a-zA-Z0-9._-]/g, "-");
    return `${cleanProv}__${cleanModel}`;
}

function normalizeAccountsList(optionsObj) {
    if (!optionsObj || typeof optionsObj !== "object") return [];
    const accounts = [];
    if (Array.isArray(optionsObj.accounts)) {
        for (const acc of optionsObj.accounts) {
            if (!acc || typeof acc !== "object") continue;
            const k = String(acc.apiKey || "").trim();
            if (!k) continue;
            accounts.push({
                id: String(acc.id || crypto.randomUUID()),
                name: String(acc.name || "Account").trim(),
                apiKey: k,
                active: !!acc.active,
                enabled: acc.enabled !== false
            });
        }
    }
    // Also import legacy single options.apiKey or options.apiKeys if not already in accounts
    const legacyKeys = [];
    if (typeof optionsObj.apiKey === "string" && optionsObj.apiKey.trim()) {
        legacyKeys.push(optionsObj.apiKey.trim());
    } else if (Array.isArray(optionsObj.apiKey)) {
        for (const k of optionsObj.apiKey) if (typeof k === "string" && k.trim()) legacyKeys.push(k.trim());
    }
    if (Array.isArray(optionsObj.apiKeys)) {
        for (const k of optionsObj.apiKeys) if (typeof k === "string" && k.trim()) legacyKeys.push(k.trim());
    }
    for (const lk of legacyKeys) {
        if (!accounts.some(a => a.apiKey === lk)) {
            accounts.push({
                id: `acc-${crypto.createHash("sha1").update(lk).digest("hex").slice(0, 8)}`,
                name: accounts.length === 0 ? "Account 1" : `Account ${accounts.length + 1}`,
                apiKey: lk,
                active: accounts.length === 0,
                enabled: true
            });
        }
    }
    if (accounts.length > 0 && !accounts.some(a => a.active)) {
        accounts[0].active = true;
    }
    return accounts;
}

function extractApiKeysFromOptions(optionsObj) {
    const accounts = normalizeAccountsList(optionsObj).filter(a => a.enabled !== false);
    if (!accounts.length) return [];
    const activeAcc = accounts.find(a => a.active) || accounts[0];
    const ordered = [activeAcc.apiKey];
    for (const acc of accounts) {
        if (acc.apiKey && !ordered.includes(acc.apiKey)) {
            ordered.push(acc.apiKey);
        }
    }
    return ordered;
}

function getActiveApiKey() {
    const cfg = loadParsedAgyConfig();
    const googleProv = cfg.provider?.google;
    const gKeys = extractApiKeysFromOptions(googleProv?.options);
    if (gKeys.length > 0) return gKeys[0];
    for (const p of Object.values(cfg.provider || {})) {
        const ks = extractApiKeysFromOptions(p?.options);
        if (ks.length > 0) return ks[0];
    }
    return "";
}

// ---------------------------------------------------------------------------
// Build Admin Settings & Route Table from ~/.gemini/antigravity.json
// ---------------------------------------------------------------------------
async function buildDynamicAdminSettings(gwPort) {
    const cfg = loadParsedAgyConfig();
    const providers = cfg.provider || {};
    const providerEntries = Object.entries(providers);
    const hasMultipleProviders = providerEntries.length > 1;

    modelRouteTable.clear();
    for (const k of Object.keys(dynamicContextLimits)) delete dynamicContextLimits[k];

    const adminModelList = [];
    let defaultAssigned = false;

    for (const [provId, provCfg] of providerEntries) {
        if (!provCfg || typeof provCfg !== "object") continue;
        const provName = String(provCfg.name || provId).trim();
        const protocol = detectProviderProtocol(provId, provCfg);
        const apiKeys = extractApiKeysFromOptions(provCfg.options);
        const baseURL = String(
            provCfg.options?.baseURL ||
            (protocol === "google-genai" ? "https://generativelanguage.googleapis.com/v1beta" : "https://api.openai.com/v1")
        ).trim().replace(/\/+$/, "");
        const customHeaders = (provCfg.options?.headers && typeof provCfg.options.headers === "object")
            ? provCfg.options.headers
            : {};

        const modelsObj = (provCfg.models && typeof provCfg.models === "object") ? provCfg.models : {};
        for (const [rawModelKey, mCfg] of Object.entries(modelsObj)) {
            if (!mCfg || typeof mCfg !== "object") continue;
            const gwBaseId = sanitizeGatewayModelBaseId(provId, rawModelKey, protocol);
            const rawDisplayName = String(mCfg.name || rawModelKey).trim();
            const displayPrefix = (hasMultipleProviders && protocol !== "google-genai") ? `${provName} / ` : "";
            const baseLabel = `${displayPrefix}${rawDisplayName}`;

            const maxTokens = Number(mCfg.limit?.context) || Number(mCfg.maxTokens) || 262144;
            const maxOutputTokens = Math.min(Number(mCfg.limit?.output) || Number(mCfg.maxOutputTokens) || 32768, maxTokens);
            const supportsThinking = mCfg.reasoning !== false && Boolean(mCfg.reasoning ?? (protocol === "google-genai"));
            const inputModalities = Array.isArray(mCfg.modalities?.input) ? mCfg.modalities.input : [];
            const supportsImages = Boolean(mCfg.attachment || inputModalities.includes("image"));

            modelRouteTable.set(gwBaseId.toLowerCase(), {
                providerId: provId,
                providerName: provName,
                protocol,
                baseURL,
                apiKeys,
                headers: customHeaders,
                upstreamModelId: rawModelKey,
                gwBaseId,
                displayName: baseLabel,
                maxTokens,
                maxOutputTokens,
                supportsThinking,
                supportsImages,
                customCostCfg: mCfg.cost || null,
                interleaved: mCfg.interleaved || null,
                tpmLimit: protocol === "google-genai"
                    ? (rawModelKey.startsWith("gemma-4-26b") ? 16000 : rawModelKey.startsWith("gemma-4") ? 32000 : 2000000)
                    : 1000000
            });

            dynamicContextLimits[gwBaseId.toLowerCase()] = maxTokens;
            dynamicContextLimits[baseLabel.toLowerCase()] = maxTokens;

            if (supportsThinking) {
                for (const eff of EFFORT_LEVELS) {
                    const isDef = !defaultAssigned && ((rawModelKey === "gemini-4-carbon" && eff.suffix === "high") || eff.suffix === "high");
                    if (isDef) defaultAssigned = true;
                    const fullMid = `${gwBaseId}-${eff.suffix}`;
                    const fullLabel = `${baseLabel} (${eff.label})`;
                    dynamicContextLimits[fullMid.toLowerCase()] = maxTokens;
                    dynamicContextLimits[fullLabel.toLowerCase()] = maxTokens;
                    adminModelList.push({
                        modelId: fullMid,
                        displayName: fullLabel,
                        isDefault: isDef,
                        supportsThinking: true,
                        supportsImages,
                        thinkingBudget: eff.budget,
                        maxTokens,
                        maxOutputTokens
                    });
                }
            } else {
                const isDef = !defaultAssigned;
                if (isDef) defaultAssigned = true;
                adminModelList.push({
                    modelId: gwBaseId,
                    displayName: baseLabel,
                    isDefault: isDef,
                    supportsThinking: false,
                    supportsImages,
                    maxTokens,
                    maxOutputTokens
                });
            }
        }
    }

    // Fallback safety if user emptied all models so LS still boots cleanly
    if (adminModelList.length === 0) {
        adminModelList.push({
            modelId: "unconfigured-model",
            displayName: "Add Provider/Models in Settings -> Providers (JSON)",
            isDefault: true,
            supportsThinking: false,
            supportsImages: false,
            maxTokens: 1048576,
            maxOutputTokens: 32768
        });
    } else if (!adminModelList.some(m => m.isDefault)) {
        adminModelList[0].isDefault = true;
    }

    const allIds = new Set(adminModelList.map(m => m.modelId));
    const pickTier = (candidates) => {
        const hit = candidates.filter(id => allIds.has(id));
        return hit.length > 0 ? hit : [adminModelList[0].modelId];
    };

    return {
        gateway: {
            url: `https://127.0.0.1:${gwPort}`,
            wireProtocol: "genai"
        },
        models: {
            tiers: {
                pro: pickTier(["gemini-4-carbon-high", "gemini-4-argon-high"]),
                flash: pickTier(["gemini-4-hydrogen-medium", "gemini-4-hydrogen-low"]),
                flashLite: pickTier(["gemini-4-hydrogen-low", "gemini-4-argon-low"])
            },
            list: adminModelList
        }
    };
}

async function syncAdminSettingsFiles(gwPort, forceWrite = false) {
    const cfg = await buildDynamicAdminSettings(gwPort);
    if (!forceWrite && getCurrentAuthMode() === "google_oauth") {
        removeAdminSettingsFilesForOAuthMode();
        return cfg;
    }
    const raw = Buffer.from(JSON.stringify(cfg, null, 2), "utf8");
    let wroteAny = false;
    for (const p of getAdminSettingsTargetPaths()) {
        try {
            fs.mkdirSync(path.dirname(p), { recursive: true });
            fs.writeFileSync(p, raw);
            wroteAny = true;
        } catch {
            // System-wide path (/etc/antigravity or /Library/...) may require root; user-level or Tier 3 discovery handles fallback
        }
    }
    if (wroteAny) {
        console.log(`[GatewayForwarder] Synced ${cfg.models.list.length} model entries from antigravity.json into admin_settings.json`);
    }
    return cfg;
}

// ---------------------------------------------------------------------------
// Live Usage & Quota Summary (Dynamic per Provider in antigravity.json)
// ---------------------------------------------------------------------------
function recordModelUsage(routeKey, tokensUsed) {
    const key = String(routeKey || "").toLowerCase();
    const now = Date.now();
    const list = modelUsageEvents.get(key) || [];
    list.push({ ts: now, tokens: Math.max(0, Number(tokensUsed) || 0) });
    while (list.length > 0 && now - list[0].ts > 60000) {
        list.shift();
    }
    modelUsageEvents.set(key, list);
    modelTotalRequests.set(key, (modelTotalRequests.get(key) || 0) + 1);
}

function formatTokenShort(n) {
    if (n >= 1000000) return `${(n / 1048576).toFixed(n % 1048576 === 0 ? 0 : 1)}M`;
    if (n >= 1000) return `${Math.round(n / 1024)}K`;
    return String(n);
}

function buildLiveQuotaSummaryResponse() {
    const now = Date.now();
    const groupsMap = new Map();

    for (const [routeKey, route] of modelRouteTable.entries()) {
        const grpTitle = `${route.providerName} (${route.protocol === "google-genai" ? "GenAI" : "OpenAI-Compatible"})`;
        if (!groupsMap.has(grpTitle)) {
            groupsMap.set(grpTitle, {
                displayName: grpTitle,
                description: `Configured in ~/.gemini/antigravity.json · ${route.baseURL}`,
                buckets: []
            });
        }
        const events = (modelUsageEvents.get(routeKey) || []).filter(e => now - e.ts <= 60000);
        modelUsageEvents.set(routeKey, events);
        const usedLastMin = events.reduce((acc, e) => acc + e.tokens, 0);
        const totalReqs = modelTotalRequests.get(routeKey) || 0;
        const remaining = Math.max(0, Math.min(1, 1 - usedLastMin / (route.tpmLimit || 1000000)));
        const ctxNote = `${formatTokenShort(route.maxTokens)} ctx · ${formatTokenShort(route.maxOutputTokens)} out`;
        const desc = totalReqs > 0
            ? `${usedLastMin.toLocaleString()} tok/min · ${totalReqs} reqs · ${ctxNote}`
            : ctxNote;

        groupsMap.get(grpTitle).buckets.push({
            bucketId: route.gwBaseId,
            displayName: route.displayName,
            description: desc,
            window: "",
            disabled: route.apiKeys.length === 0,
            remaining: {
                case: "remainingFraction",
                value: route.apiKeys.length === 0 ? 0 : remaining
            }
        });
    }

    return {
        modelContextLimits: dynamicContextLimits,
        telemetry: getTelemetrySnapshot(),
        cooldowns: getQuotaCooldownsOverview(),
        response: {
            description: "Google Gemini Max Plan & Custom Providers (~/.gemini/antigravity.json)",
            groups: Array.from(groupsMap.values())
        }
    };
}

// ---------------------------------------------------------------------------
// Bidirectional Google GenAI <-> OpenAI /chat/completions Protocol Translator
// ---------------------------------------------------------------------------
function sanitizeJsonSchemaForOpenAI(schema) {
    if (!schema || typeof schema !== "object") return schema;
    if (Array.isArray(schema)) return schema.map(sanitizeJsonSchemaForOpenAI);

    const out = {};
    for (const [k, v] of Object.entries(schema)) {
        if (k === "propertyOrdering" || k === "nullable") continue;
        if (k === "type" && typeof v === "string") {
            out.type = v.toLowerCase();
        } else if (k === "properties" && v && typeof v === "object") {
            out.properties = {};
            for (const [pk, pv] of Object.entries(v)) {
                out.properties[pk] = sanitizeJsonSchemaForOpenAI(pv);
            }
        } else if (k === "items") {
            out.items = sanitizeJsonSchemaForOpenAI(v);
        } else if (k === "anyOf" || k === "oneOf" || k === "allOf") {
            out[k] = Array.isArray(v) ? v.map(sanitizeJsonSchemaForOpenAI) : v;
        } else {
            out[k] = v;
        }
    }
    if (out.type === "object" && !out.properties) {
        out.properties = {};
    }
    return out;
}

function convertGenAiRequestToOpenAi(rawGenAiBody, route, isStreaming) {
    const genAiBody = sanitizeTrailingModelTurn(JSON.parse(JSON.stringify(rawGenAiBody || {})));
    const messages = [];
    const provSig = `${route.providerId || ""} ${route.baseURL || ""}`.toLowerCase();
    const usesReasoningContentField =
        route.interleaved === "reasoning_content" ||
        (route.interleaved !== "none" && /deepseek|moonshot|kimi|dashscope|aliyuncs|z\.ai|bigmodel|siliconflow/.test(provSig));

    // 1. System Instruction
    if (genAiBody?.systemInstruction?.parts) {
        const sysText = genAiBody.systemInstruction.parts
            .map(p => p.text || "")
            .filter(Boolean)
            .join("\n\n");
        if (sysText) {
            messages.push({ role: "system", content: sysText });
        }
    }

    // 2. Conversation Turns (text, thoughts, images, functionCall, functionResponse)
    const pendingCallIdsByName = new Map();
    let callSeq = 1;

    for (const turn of (genAiBody?.contents || [])) {
        const role = turn.role === "model" ? "assistant" : "user";
        const parts = Array.isArray(turn.parts) ? turn.parts : [];

        if (role === "assistant") {
            let textBuf = "";
            let thoughtBuf = "";
            const toolCalls = [];

            for (const p of parts) {
                if (p.thought && typeof p.text === "string") {
                    thoughtBuf += p.text;
                } else if (typeof p.text === "string") {
                    textBuf += p.text;
                } else if (p.functionCall) {
                    const fnName = p.functionCall.name || "tool";
                    const callId = p.functionCall.id || `call_${callSeq++}_${fnName}`;
                    const q = pendingCallIdsByName.get(fnName) || [];
                    q.push(callId);
                    pendingCallIdsByName.set(fnName, q);

                    toolCalls.push({
                        id: callId,
                        type: "function",
                        function: {
                            name: fnName,
                            arguments: JSON.stringify(p.functionCall.args || {})
                        }
                    });
                }
            }

            if (!textBuf && !toolCalls.length && !thoughtBuf) continue;
            const msg = { role: "assistant", content: textBuf || (toolCalls.length ? null : "") };
            if (usesReasoningContentField && (route.supportsThinking || thoughtBuf)) {
                msg.reasoning_content = thoughtBuf || "";
            }
            if (toolCalls.length > 0) {
                msg.tool_calls = toolCalls;
            }
            messages.push(msg);
        } else {
            // User role: may contain functionResponse parts and/or user text/image parts
            const contentParts = [];
            for (const p of parts) {
                if (p.functionResponse) {
                    const fnName = p.functionResponse.name || "tool";
                    const q = pendingCallIdsByName.get(fnName);
                    const matchedId = p.functionResponse.id || (q && q.length ? q.shift() : `call_resp_${callSeq++}`);
                    const respVal = p.functionResponse.response;
                    const respStr = typeof respVal === "string" ? respVal : JSON.stringify(respVal ?? {});
                    messages.push({
                        role: "tool",
                        tool_call_id: matchedId,
                        content: respStr
                    });
                } else if (typeof p.text === "string") {
                    contentParts.push({ type: "text", text: p.text });
                } else if (p.inlineData && p.inlineData.data) {
                    const mime = p.inlineData.mimeType || "image/png";
                    contentParts.push({
                        type: "image_url",
                        image_url: { url: `data:${mime};base64,${p.inlineData.data}` }
                    });
                }
            }

            if (contentParts.length === 1 && contentParts[0].type === "text") {
                messages.push({ role: "user", content: contentParts[0].text });
            } else if (contentParts.length > 0) {
                messages.push({ role: "user", content: contentParts });
            }
        }
    }

    const openAiPayload = {
        model: route.upstreamModelId,
        messages,
        stream: isStreaming
    };
    if (isStreaming && !/mistral|perplexity|cohere/i.test(provSig)) {
        openAiPayload.stream_options = { include_usage: true };
    }

    // 3. Tools
    const openAiTools = [];
    for (const tGroup of (genAiBody?.tools || [])) {
        for (const fd of (tGroup.functionDeclarations || [])) {
            const rawParams = fd.parametersJsonSchema || fd.parameters || { type: "object", properties: {} };
            openAiTools.push({
                type: "function",
                function: {
                    name: fd.name,
                    description: fd.description || "",
                    parameters: sanitizeJsonSchemaForOpenAI(rawParams)
                }
            });
        }
    }
    if (openAiTools.length > 0) {
        openAiPayload.tools = openAiTools;
    }

    // 4. Generation Config
    const gc = genAiBody?.generationConfig || {};
    const isOSeriesModel = /^(o1|o3|o4|gpt-5)/i.test(String(route.upstreamModelId || ""));
    if (typeof gc.temperature === "number" && !/^(o1|o3|o4)/i.test(String(route.upstreamModelId || ""))) {
        openAiPayload.temperature = gc.temperature;
    }
    if (typeof gc.topP === "number" && !/^(o1|o3|o4)/i.test(String(route.upstreamModelId || ""))) {
        openAiPayload.top_p = gc.topP;
    }
    if (Array.isArray(gc.stopSequences) && gc.stopSequences.length > 0) openAiPayload.stop = gc.stopSequences;
    const reqMaxOut = Number(gc.maxOutputTokens) || route.maxOutputTokens || 16384;
    const cappedOut = Math.min(reqMaxOut, route.maxOutputTokens || reqMaxOut);
    if (isOSeriesModel && (/api\.openai\.com/.test(provSig) || route.protocol === "azure-openai")) {
        openAiPayload.max_completion_tokens = cappedOut;
    } else {
        openAiPayload.max_tokens = cappedOut;
    }

    return openAiPayload;
}

function forwardToOpenAiCompatibleProvider(req, res, route, genAiBody, isStreaming, keyIdx = 0, orderedKeys = null) {
    const keysList = orderedKeys || getOrderedApiKeysForModel(route.providerId, route.apiKeys, route.upstreamModelId);
    if (!keysList.length) {
        res.writeHead(401, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({
            error: {
                code: 401,
                message: `No API key configured for provider "${route.providerName}" in ~/.gemini/antigravity.json.`
            }
        }));
    }

    const reqStartTs = Date.now();
    let firstTokenTs = 0;
    const activeKey = keysList[keyIdx];
    const openAiPayload = convertGenAiRequestToOpenAi(genAiBody || {}, route, isStreaming);
    const outBuf = Buffer.from(JSON.stringify(openAiPayload), "utf8");

    let targetUrl;
    try {
        const base = route.baseURL.endsWith("/") ? route.baseURL : `${route.baseURL}/`;
        targetUrl = new URL("chat/completions", base);
    } catch (err) {
        res.writeHead(400, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: { code: 400, message: `Invalid baseURL for ${route.providerName}: ${err.message}` } }));
    }

    const isHttp = targetUrl.protocol === "http:";
    const isAzure = route.protocol === "azure-openai";
    const reqHeaders = {
        "Content-Type": "application/json",
        "Accept": isStreaming ? "text/event-stream" : "application/json",
        ...(isAzure ? { "api-key": activeKey } : { "Authorization": `Bearer ${activeKey}` }),
        "User-Agent": "antigravity/2.29.1",
        ...route.headers,
        "Content-Length": outBuf.length
    };

    const upReq = createProxiedRequest(!isHttp, {
        protocol: targetUrl.protocol,
        hostname: targetUrl.hostname,
        port: targetUrl.port || (isHttp ? 80 : 443),
        path: targetUrl.pathname + targetUrl.search,
        method: "POST",
        headers: reqHeaders
    }, (upRes) => {
        const status = upRes.statusCode || 200;
        if (status === 429 || status === 503) {
            markApiKeyModelQuotaExhausted(route.providerId, activeKey, route.upstreamModelId, String(status));
            if (keyIdx + 1 < keysList.length) {
                upRes.resume();
                return forwardToOpenAiCompatibleProvider(req, res, route, genAiBody, isStreaming, keyIdx + 1, keysList);
            }
        }

        if (status >= 400) {
            const errChunks = [];
            upRes.on("data", d => errChunks.push(d));
            upRes.on("end", () => {
                const rawErr = Buffer.concat(errChunks).toString("utf8");
                let errMsg = rawErr;
                try {
                    const ej = JSON.parse(rawErr);
                    errMsg = ej.error?.message || ej.message || rawErr;
                } catch {}
                res.writeHead(status, { "Content-Type": "application/json" });
                res.end(JSON.stringify({
                    error: {
                        code: status,
                        message: `[${route.providerName} / ${route.upstreamModelId}] ${errMsg}`,
                        status: status === 429 ? "RESOURCE_EXHAUSTED" : "INVALID_ARGUMENT"
                    }
                }));
            });
            return;
        }

        const responseId = `agy-${crypto.randomUUID().slice(0, 12)}`;

        if (!isStreaming) {
            const chunks = [];
            upRes.on("data", d => chunks.push(d));
            upRes.on("end", () => {
                try {
                    const oj = JSON.parse(Buffer.concat(chunks).toString("utf8"));
                    const choice = oj.choices?.[0]?.message || {};
                    const parts = [];
                    if (choice.reasoning_content) parts.push({ thought: true, text: String(choice.reasoning_content) });
                    if (choice.content) parts.push({ text: String(choice.content) });
                    for (const tc of (choice.tool_calls || [])) {
                        let parsedArgs = {};
                        try { parsedArgs = JSON.parse(tc.function?.arguments || "{}"); } catch {}
                        parts.push({
                            functionCall: {
                                id: tc.id || `call_${crypto.randomUUID().slice(0, 8)}`,
                                name: tc.function?.name || "tool",
                                args: parsedArgs
                            }
                        });
                    }
                    if (!parts.length) parts.push({ text: "" });
                    const pTok = oj.usage?.prompt_tokens || Math.round(outBuf.length / 4);
                    const cTok = oj.usage?.completion_tokens || 32;
                    recordModelUsage(route.gwBaseId, pTok);
                    recordRequestTelemetry({
                        modelId: route.upstreamModelId,
                        providerName: route.providerName,
                        requestStartTs: reqStartTs,
                        firstTokenTs: Date.now(),
                        endTs: Date.now(),
                        promptTokens: pTok,
                        completionTokens: cTok,
                        customCostCfg: route.customCostCfg
                    });

                    res.writeHead(200, { "Content-Type": "application/json" });
                    res.end(JSON.stringify({
                        candidates: [{ content: { role: "model", parts }, finishReason: "STOP", index: 0 }],
                        usageMetadata: { promptTokenCount: pTok, candidatesTokenCount: cTok, totalTokenCount: pTok + cTok },
                        modelVersion: route.upstreamModelId,
                        responseId
                    }));
                } catch (err) {
                    res.writeHead(502, { "Content-Type": "application/json" });
                    res.end(JSON.stringify({ error: { code: 502, message: err.message } }));
                }
            });
            return;
        }

        // Streaming SSE Translation: OpenAI SSE -> Google GenAI SSE
        res.writeHead(200, {
            "Content-Type": "text/event-stream; charset=UTF-8",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive"
        });

        let sseBuf = "";
        const toolCallAccum = new Map(); // index -> { id, name, argsStr }
        let promptTok = Math.round(outBuf.length / 4);
        let complTok = 0;
        let inThinkTag = false;
        let thinkTagBuf = "";
        let finalized = false;

        const emitGenAiSseParts = (parts, finishReason = null) => {
            if (!firstTokenTs && !finishReason) firstTokenTs = Date.now();
            if (!finishReason) {
                tickStreamingTelemetry({
                    modelId: route.upstreamModelId,
                    providerName: route.providerName,
                    requestStartTs: reqStartTs,
                    firstTokenTs,
                    streamedTokensSoFar: complTok
                });
            }
            const cand = {
                content: { role: "model", parts },
                index: 0
            };
            if (finishReason) cand.finishReason = finishReason;
            const frame = {
                candidates: [cand],
                usageMetadata: {
                    promptTokenCount: promptTok,
                    candidatesTokenCount: complTok,
                    totalTokenCount: promptTok + complTok
                },
                modelVersion: route.upstreamModelId,
                responseId
            };
            res.write(`data: ${JSON.stringify(frame)}\r\n\r\n`);
        };

        const flushFinalSse = () => {
            if (finalized) return;
            finalized = true;
            if (thinkTagBuf) {
                emitGenAiSseParts([inThinkTag ? { thought: true, text: thinkTagBuf } : { text: thinkTagBuf }]);
                thinkTagBuf = "";
            }
            if (toolCallAccum.size > 0) {
                const tcParts = [];
                for (const [, tc] of Array.from(toolCallAccum.entries()).sort((a, b) => a[0] - b[0])) {
                    let parsedArgs = {};
                    try { parsedArgs = JSON.parse(tc.argsStr || "{}"); } catch {}
                    tcParts.push({
                        functionCall: {
                            id: tc.id || `call_${crypto.randomUUID().slice(0, 8)}`,
                            name: tc.name || "tool",
                            args: parsedArgs
                        }
                    });
                }
                toolCallAccum.clear();
                emitGenAiSseParts(tcParts);
            }
            recordModelUsage(route.gwBaseId, promptTok);
            recordRequestTelemetry({
                modelId: route.upstreamModelId,
                providerName: route.providerName,
                requestStartTs: reqStartTs,
                firstTokenTs: firstTokenTs || Date.now(),
                endTs: Date.now(),
                promptTokens: promptTok,
                completionTokens: complTok,
                customCostCfg: route.customCostCfg
            });
            emitGenAiSseParts([{ text: "" }], "STOP");
        };

        const processContentWithThinkTags = (chunkStr) => {
            thinkTagBuf += chunkStr;
            while (thinkTagBuf.length > 0) {
                if (!inThinkTag) {
                    const openIdx = thinkTagBuf.indexOf("<think>");
                    if (openIdx === -1) {
                        // Keep partial '<thin' suffix in buffer just in case
                        const partialLt = thinkTagBuf.lastIndexOf("<");
                        if (partialLt >= 0 && "<think>".startsWith(thinkTagBuf.slice(partialLt))) {
                            const safeText = thinkTagBuf.slice(0, partialLt);
                            if (safeText) emitGenAiSseParts([{ text: safeText }]);
                            thinkTagBuf = thinkTagBuf.slice(partialLt);
                        } else {
                            emitGenAiSseParts([{ text: thinkTagBuf }]);
                            thinkTagBuf = "";
                        }
                        break;
                    }
                    const before = thinkTagBuf.slice(0, openIdx);
                    if (before) emitGenAiSseParts([{ text: before }]);
                    thinkTagBuf = thinkTagBuf.slice(openIdx + 7);
                    inThinkTag = true;
                } else {
                    const closeIdx = thinkTagBuf.indexOf("</think>");
                    if (closeIdx === -1) {
                        const partialLt = thinkTagBuf.lastIndexOf("<");
                        if (partialLt >= 0 && "</think>".startsWith(thinkTagBuf.slice(partialLt))) {
                            const safeThought = thinkTagBuf.slice(0, partialLt);
                            if (safeThought) emitGenAiSseParts([{ thought: true, text: safeThought }]);
                            thinkTagBuf = thinkTagBuf.slice(partialLt);
                        } else {
                            emitGenAiSseParts([{ thought: true, text: thinkTagBuf }]);
                            thinkTagBuf = "";
                        }
                        break;
                    }
                    const thoughtPart = thinkTagBuf.slice(0, closeIdx);
                    if (thoughtPart) emitGenAiSseParts([{ thought: true, text: thoughtPart }]);
                    thinkTagBuf = thinkTagBuf.slice(closeIdx + 8);
                    inThinkTag = false;
                }
            }
        };

        const oaiUtf8Dec = new StringDecoder("utf8");
        upRes.on("data", (chunk) => {
            sseBuf += oaiUtf8Dec.write(chunk);
            let nlIdx;
            while ((nlIdx = sseBuf.indexOf("\n")) !== -1) {
                const line = sseBuf.slice(0, nlIdx).trim();
                sseBuf = sseBuf.slice(nlIdx + 1);
                if (!line.startsWith("data:")) continue;
                const dataStr = line.slice(5).trim();
                if (!dataStr) continue;
                if (dataStr === "[DONE]") {
                    flushFinalSse();
                    continue;
                }
                let evt;
                try {
                    evt = JSON.parse(dataStr);
                } catch {
                    continue;
                }
                if (evt.usage) {
                    if (evt.usage.prompt_tokens) promptTok = Number(evt.usage.prompt_tokens);
                    if (evt.usage.completion_tokens) complTok = Number(evt.usage.completion_tokens);
                }
                const choice = evt.choices?.[0];
                if (!choice) continue;
                const delta = choice.delta || {};

                const reasoningDelta = delta.reasoning_content ?? delta.reasoning;
                if (typeof reasoningDelta === "string" && reasoningDelta.length > 0) {
                    complTok += Math.max(1, Math.round(reasoningDelta.length / 4));
                    emitGenAiSseParts([{ thought: true, text: reasoningDelta }]);
                }
                if (typeof delta.content === "string" && delta.content.length > 0) {
                    complTok += Math.max(1, Math.round(delta.content.length / 4));
                    processContentWithThinkTags(delta.content);
                }
                if (Array.isArray(delta.tool_calls)) {
                    for (const tc of delta.tool_calls) {
                        const idx = typeof tc.index === "number" ? tc.index : 0;
                        const cur = toolCallAccum.get(idx) || { id: "", name: "", argsStr: "" };
                        if (tc.id) cur.id = tc.id;
                        if (tc.function?.name) cur.name += tc.function.name;
                        if (tc.function?.arguments) cur.argsStr += tc.function.arguments;
                        toolCallAccum.set(idx, cur);
                    }
                }
            }
        });

        upRes.on("end", () => {
            const rem = oaiUtf8Dec.end();
            if (rem) sseBuf += rem;
            flushFinalSse();
            res.end();
        });
        upRes.on("error", () => {
            flushFinalSse();
            res.end();
        });
    });

    upReq.on("error", (err) => {
        if (!res.headersSent) {
            res.writeHead(502, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: { code: 502, message: `[${route.providerName}] ${err.message}` } }));
        }
    });

    upReq.end(outBuf);
}

// ---------------------------------------------------------------------------
// Bidirectional Google GenAI <-> Anthropic Messages (/v1/messages) Translator
// ---------------------------------------------------------------------------
// Session cache of Anthropic thinking cryptographic signatures keyed by tool_use_id or thought text hash
const anthropicThinkingSigCache = new Map();
function rememberAnthropicThinkingSig(keyStr, thinkingText, signature) {
    if (!keyStr || !signature) return;
    if (anthropicThinkingSigCache.size > 400) {
        const firstKey = anthropicThinkingSigCache.keys().next().value;
        anthropicThinkingSigCache.delete(firstKey);
    }
    anthropicThinkingSigCache.set(keyStr, { thinking: thinkingText || "", signature });
}

function forwardToAnthropicMessagesProvider(req, res, route, rawGenAiBody, isStreaming, selectedEffort, keyIdx = 0, orderedKeys = null) {
    const keysList = orderedKeys || getOrderedApiKeysForModel(route.providerId, route.apiKeys, route.upstreamModelId);
    if (!keysList.length) {
        res.writeHead(401, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({
            error: { code: 401, message: `No API key configured for "${route.providerName}" in ~/.gemini/antigravity.json.` }
        }));
    }

    const genAiBody = sanitizeTrailingModelTurn(JSON.parse(JSON.stringify(rawGenAiBody || {})));
    const reqStartTs = Date.now();
    let firstTokenTs = 0;
    const activeKey = keysList[keyIdx];
    const systemText = (genAiBody?.systemInstruction?.parts || [])
        .map(p => p.text || "")
        .filter(Boolean)
        .join("\n\n");

    const anthropicMessages = [];
    const pendingToolIdsByName = new Map();
    let callSeq = 1;
    let hasUnsignedAssistantToolTurn = false;

    for (const turn of (genAiBody?.contents || [])) {
        const role = turn.role === "model" ? "assistant" : "user";
        const parts = Array.isArray(turn.parts) ? turn.parts : [];
        const blocks = [];

        if (role === "assistant") {
            let turnThoughtText = "";
            const otherBlocks = [];
            const turnToolIds = [];

            for (const p of parts) {
                if (p.thought && typeof p.text === "string") {
                    turnThoughtText += p.text;
                } else if (typeof p.text === "string" && p.text.length > 0) {
                    otherBlocks.push({ type: "text", text: p.text });
                } else if (p.functionCall) {
                    const fnName = p.functionCall.name || "tool";
                    const callId = (p.functionCall.id || `toolu_${callSeq++}_${fnName}`).replace(/[^a-zA-Z0-9_-]/g, "_");
                    const q = pendingToolIdsByName.get(fnName) || [];
                    q.push(callId);
                    pendingToolIdsByName.set(fnName, q);
                    turnToolIds.push(callId);
                    otherBlocks.push({
                        type: "tool_use",
                        id: callId,
                        name: fnName,
                        input: p.functionCall.args || {}
                    });
                }
            }

            let signedThinkingBlock = null;
            for (const tid of turnToolIds) {
                const cached = anthropicThinkingSigCache.get(`tool:${tid}`);
                if (cached && cached.signature) {
                    signedThinkingBlock = { type: "thinking", thinking: cached.thinking || turnThoughtText, signature: cached.signature };
                    break;
                }
            }
            if (!signedThinkingBlock && turnThoughtText) {
                const thHash = crypto.createHash("sha1").update(turnThoughtText).digest("hex");
                const cached = anthropicThinkingSigCache.get(`hash:${thHash}`);
                if (cached && cached.signature) {
                    signedThinkingBlock = { type: "thinking", thinking: turnThoughtText, signature: cached.signature };
                }
            }

            if (signedThinkingBlock) {
                blocks.push(signedThinkingBlock);
            } else if (turnToolIds.length > 0) {
                hasUnsignedAssistantToolTurn = true;
            }
            blocks.push(...otherBlocks);
        } else {
            for (const p of parts) {
                if (p.functionResponse) {
                    const fnName = p.functionResponse.name || "tool";
                    const q = pendingToolIdsByName.get(fnName);
                    const matchedId = (p.functionResponse.id || (q && q.length ? q.shift() : `toolu_${callSeq++}`)).replace(/[^a-zA-Z0-9_-]/g, "_");
                    const respVal = p.functionResponse.response;
                    blocks.push({
                        type: "tool_result",
                        tool_use_id: matchedId,
                        content: typeof respVal === "string" ? respVal : JSON.stringify(respVal ?? {})
                    });
                } else if (typeof p.text === "string" && p.text.length > 0) {
                    blocks.push({ type: "text", text: p.text });
                } else if (p.inlineData && p.inlineData.data) {
                    blocks.push({
                        type: "image",
                        source: {
                            type: "base64",
                            media_type: p.inlineData.mimeType || "image/png",
                            data: p.inlineData.data
                        }
                    });
                }
            }
        }

        if (blocks.length > 0) {
            const prev = anthropicMessages[anthropicMessages.length - 1];
            if (prev && prev.role === role) {
                prev.content.push(...blocks);
                if (role === "user") {
                    // Anthropic requires all tool_result blocks at the start of user content
                    const trs = prev.content.filter(b => b.type === "tool_result");
                    const rest = prev.content.filter(b => b.type !== "tool_result");
                    prev.content = [...trs, ...rest];
                }
            } else {
                if (role === "user") {
                    const trs = blocks.filter(b => b.type === "tool_result");
                    const rest = blocks.filter(b => b.type !== "tool_result");
                    anthropicMessages.push({ role, content: [...trs, ...rest] });
                } else {
                    anthropicMessages.push({ role, content: blocks });
                }
            }
        }
    }

    // Anthropic strictly requires messages[0].role === "user"
    while (anthropicMessages.length > 0 && anthropicMessages[0].role !== "user") {
        anthropicMessages.shift();
    }
    // Prefilling trailing assistant messages is disallowed when thinking is enabled
    if (route.supportsThinking && anthropicMessages.length > 1 && anthropicMessages[anthropicMessages.length - 1].role === "assistant") {
        anthropicMessages.push({ role: "user", content: [{ type: "text", text: "Continue." }] });
    }

    const anthropicTools = [];
    for (const tGroup of (genAiBody?.tools || [])) {
        for (const fd of (tGroup.functionDeclarations || [])) {
            const rawParams = fd.parametersJsonSchema || fd.parameters || { type: "object", properties: {} };
            anthropicTools.push({
                name: fd.name,
                description: fd.description || "",
                input_schema: sanitizeJsonSchemaForOpenAI(rawParams)
            });
        }
    }

    const gc = genAiBody?.generationConfig || {};
    const maxOut = Math.min(Number(gc.maxOutputTokens) || route.maxOutputTokens || 16384, route.maxOutputTokens || 64000);
    const bodyObj = {
        model: route.upstreamModelId,
        max_tokens: maxOut,
        messages: anthropicMessages.length ? anthropicMessages : [{ role: "user", content: [{ type: "text", text: "Hello" }] }],
        stream: isStreaming
    };
    if (systemText) bodyObj.system = systemText;
    if (anthropicTools.length > 0) bodyObj.tools = anthropicTools;
    if (route.supportsThinking && !hasUnsignedAssistantToolTurn) {
        const budget = Math.min((selectedEffort && EFFORT_BUDGET_MAP[selectedEffort]) || 8192, Math.max(1024, maxOut - 1024));
        if (maxOut > 2048) {
            bodyObj.thinking = { type: "enabled", budget_tokens: budget };
        }
    } else if (!route.supportsThinking && typeof gc.temperature === "number") {
        bodyObj.temperature = gc.temperature;
    }

    const outBuf = Buffer.from(JSON.stringify(bodyObj), "utf8");
    let targetUrl;
    try {
        const base = route.baseURL.endsWith("/") ? route.baseURL : `${route.baseURL}/`;
        targetUrl = base.endsWith("/messages/") ? new URL(base.slice(0, -1)) : new URL("messages", base);
    } catch (err) {
        res.writeHead(400, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: { code: 400, message: `Invalid Anthropic baseURL: ${err.message}` } }));
    }

    const isHttp = targetUrl.protocol === "http:";
    const reqHeaders = {
        "Content-Type": "application/json",
        "Accept": isStreaming ? "text/event-stream" : "application/json",
        "x-api-key": activeKey,
        "anthropic-version": "2023-06-01",
        "User-Agent": "antigravity/2.29.1",
        ...route.headers,
        "Content-Length": outBuf.length
    };

    const upReq = createProxiedRequest(!isHttp, {
        protocol: targetUrl.protocol,
        hostname: targetUrl.hostname,
        port: targetUrl.port || (isHttp ? 80 : 443),
        path: targetUrl.pathname + targetUrl.search,
        method: "POST",
        headers: reqHeaders
    }, (upRes) => {
        const status = upRes.statusCode || 200;
        if (status === 429 || status === 529 || status === 503) {
            markApiKeyModelQuotaExhausted(route.providerId, activeKey, route.upstreamModelId, String(status));
            if (keyIdx + 1 < keysList.length) {
                upRes.resume();
                return forwardToAnthropicMessagesProvider(req, res, route, genAiBody, isStreaming, selectedEffort, keyIdx + 1, keysList);
            }
        }
        if (status >= 400) {
            const ec = [];
            upRes.on("data", d => ec.push(d));
            upRes.on("end", () => {
                const rawErr = Buffer.concat(ec).toString("utf8");
                let msg = rawErr;
                try { msg = JSON.parse(rawErr).error?.message || rawErr; } catch {}
                res.writeHead(status, { "Content-Type": "application/json" });
                res.end(JSON.stringify({ error: { code: status, message: `[${route.providerName}] ${msg}` } }));
            });
            return;
        }

        const responseId = `agy-anth-${crypto.randomUUID().slice(0, 10)}`;
        if (!isStreaming) {
            const chunks = [];
            upRes.on("data", d => chunks.push(d));
            upRes.on("end", () => {
                try {
                    const aj = JSON.parse(Buffer.concat(chunks).toString("utf8"));
                    const parts = [];
                    let lastNonStreamThinking = null;
                    for (const b of (aj.content || [])) {
                        if (b.type === "thinking") {
                            parts.push({ thought: true, text: b.thinking || "" });
                            if (b.signature && b.thinking) {
                                lastNonStreamThinking = { thinking: b.thinking, signature: b.signature };
                                const thHash = crypto.createHash("sha1").update(b.thinking).digest("hex");
                                rememberAnthropicThinkingSig(`hash:${thHash}`, b.thinking, b.signature);
                            }
                        } else if (b.type === "text") {
                            parts.push({ text: b.text || "" });
                        } else if (b.type === "tool_use") {
                            if (lastNonStreamThinking && b.id) {
                                rememberAnthropicThinkingSig(`tool:${String(b.id).replace(/[^a-zA-Z0-9_-]/g, "_")}`, lastNonStreamThinking.thinking, lastNonStreamThinking.signature);
                            }
                            parts.push({ functionCall: { id: b.id, name: b.name, args: b.input || {} } });
                        }
                    }
                    if (!parts.length) parts.push({ text: "" });
                    const pTok = aj.usage?.input_tokens || Math.round(outBuf.length / 4);
                    const cTok = aj.usage?.output_tokens || 32;
                    recordModelUsage(route.gwBaseId, pTok);
                    recordRequestTelemetry({
                        modelId: route.upstreamModelId,
                        providerName: route.providerName,
                        requestStartTs: reqStartTs,
                        firstTokenTs: Date.now(),
                        endTs: Date.now(),
                        promptTokens: pTok,
                        completionTokens: cTok,
                        customCostCfg: route.customCostCfg
                    });
                    res.writeHead(200, { "Content-Type": "application/json" });
                    res.end(JSON.stringify({
                        candidates: [{ content: { role: "model", parts }, finishReason: "STOP", index: 0 }],
                        usageMetadata: { promptTokenCount: pTok, candidatesTokenCount: cTok, totalTokenCount: pTok + cTok },
                        modelVersion: route.upstreamModelId,
                        responseId
                    }));
                } catch (e) {
                    res.writeHead(502, { "Content-Type": "application/json" });
                    res.end(JSON.stringify({ error: { code: 502, message: e.message } }));
                }
            });
            return;
        }

        res.writeHead(200, {
            "Content-Type": "text/event-stream; charset=UTF-8",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive"
        });

        let sseBuf = "";
        let promptTok = Math.round(outBuf.length / 4);
        let complTok = 0;
        const activeToolBlocks = new Map();
        let streamThinkingText = "";
        let streamThinkingSig = "";
        let doneSent = false;

        const emitFrame = (parts, finishReason = null) => {
            if (!firstTokenTs && !finishReason) firstTokenTs = Date.now();
            if (!finishReason) {
                tickStreamingTelemetry({
                    modelId: route.upstreamModelId,
                    providerName: route.providerName,
                    requestStartTs: reqStartTs,
                    firstTokenTs,
                    streamedTokensSoFar: complTok
                });
            }
            const cand = { content: { role: "model", parts }, index: 0 };
            if (finishReason) cand.finishReason = finishReason;
            res.write(`data: ${JSON.stringify({
                candidates: [cand],
                usageMetadata: { promptTokenCount: promptTok, candidatesTokenCount: complTok, totalTokenCount: promptTok + complTok },
                modelVersion: route.upstreamModelId,
                responseId
            })}\r\n\r\n`);
        };

        const finishAnthropicStream = () => {
            if (doneSent) return;
            doneSent = true;
            if (streamThinkingSig && streamThinkingText) {
                const thHash = crypto.createHash("sha1").update(streamThinkingText).digest("hex");
                rememberAnthropicThinkingSig(`hash:${thHash}`, streamThinkingText, streamThinkingSig);
            }
            if (activeToolBlocks.size > 0) {
                const tcParts = [];
                for (const [, tb] of Array.from(activeToolBlocks.entries()).sort((a, b) => a[0] - b[0])) {
                    if (streamThinkingSig && tb.id) {
                        rememberAnthropicThinkingSig(`tool:${String(tb.id).replace(/[^a-zA-Z0-9_-]/g, "_")}`, streamThinkingText, streamThinkingSig);
                    }
                    let parsed = {};
                    try { parsed = JSON.parse(tb.jsonBuf || "{}"); } catch {}
                    tcParts.push({ functionCall: { id: tb.id, name: tb.name, args: parsed } });
                }
                activeToolBlocks.clear();
                emitFrame(tcParts);
            }
            recordModelUsage(route.gwBaseId, promptTok);
            recordRequestTelemetry({
                modelId: route.upstreamModelId,
                providerName: route.providerName,
                requestStartTs: reqStartTs,
                firstTokenTs: firstTokenTs || Date.now(),
                endTs: Date.now(),
                promptTokens: promptTok,
                completionTokens: complTok,
                customCostCfg: route.customCostCfg
            });
            emitFrame([{ text: "" }], "STOP");
        };

        const anthUtf8Dec = new StringDecoder("utf8");
        upRes.on("data", (chunk) => {
            sseBuf += anthUtf8Dec.write(chunk);
            let nl;
            while ((nl = sseBuf.indexOf("\n")) !== -1) {
                const line = sseBuf.slice(0, nl).trim();
                sseBuf = sseBuf.slice(nl + 1);
                if (!line.startsWith("data:")) continue;
                const dStr = line.slice(5).trim();
                if (!dStr) continue;
                let ev;
                try { ev = JSON.parse(dStr); } catch { continue; }

                if (ev.type === "message_start" && ev.message?.usage?.input_tokens) {
                    promptTok = Number(ev.message.usage.input_tokens);
                } else if (ev.type === "content_block_start" && ev.content_block?.type === "tool_use") {
                    activeToolBlocks.set(ev.index ?? 0, {
                        id: ev.content_block.id || `toolu_${crypto.randomUUID().slice(0, 8)}`,
                        name: ev.content_block.name || "tool",
                        jsonBuf: ""
                    });
                } else if (ev.type === "content_block_delta") {
                    const dl = ev.delta || {};
                    if (dl.type === "thinking_delta" && dl.thinking) {
                        streamThinkingText += dl.thinking;
                        complTok += Math.max(1, Math.round(dl.thinking.length / 4));
                        emitFrame([{ thought: true, text: dl.thinking }]);
                    } else if (dl.type === "signature_delta" && typeof dl.signature === "string") {
                        streamThinkingSig += dl.signature;
                    } else if (dl.type === "text_delta" && dl.text) {
                        complTok += Math.max(1, Math.round(dl.text.length / 4));
                        emitFrame([{ text: dl.text }]);
                    } else if (dl.type === "input_json_delta" && typeof dl.partial_json === "string") {
                        const tb = activeToolBlocks.get(ev.index ?? 0);
                        if (tb) tb.jsonBuf += dl.partial_json;
                    }
                } else if (ev.type === "message_delta" && ev.usage?.output_tokens) {
                    complTok = Number(ev.usage.output_tokens);
                } else if (ev.type === "message_stop") {
                    finishAnthropicStream();
                }
            }
        });
        upRes.on("end", () => {
            const rem = anthUtf8Dec.end();
            if (rem) sseBuf += rem;
            finishAnthropicStream();
            res.end();
        });
        upRes.on("error", () => { finishAnthropicStream(); res.end(); });
    });

    upReq.on("error", (err) => {
        if (!res.headersSent) {
            res.writeHead(502, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: { code: 502, message: `[${route.providerName}] ${err.message}` } }));
        }
    });
    upReq.end(outBuf);
}

// ---------------------------------------------------------------------------
// Config API Endpoints (/__agy_config/*) for Settings JSON & Provider Manager
// ---------------------------------------------------------------------------
async function testProviderEndpointLive(protocol, baseURL, apiKey, sampleModel) {
    const started = Date.now();
    if (!apiKey) return { valid: false, latencyMs: 0, message: "API key is empty." };

    if (protocol === "google-genai") {
        return new Promise((resolve) => {
            const req = createProxiedRequest(true, {
                hostname: "generativelanguage.googleapis.com",
                port: 443,
                path: "/v1beta/models?pageSize=20",
                method: "GET",
                headers: { "x-goog-api-key": apiKey },
                timeout: 10000
            }, (res) => {
                let raw = "";
                res.on("data", d => raw += d);
                res.on("end", () => {
                    const ms = Date.now() - started;
                    if (res.statusCode === 200) {
                        return resolve({ valid: true, latencyMs: ms, message: `Connected (${ms}ms · Google GenAI OK)` });
                    }
                    let msg = `HTTP ${res.statusCode}`;
                    try { msg = JSON.parse(raw).error?.message || msg; } catch {}
                    resolve({ valid: false, latencyMs: ms, message: msg });
                });
            });
            req.on("timeout", () => { req.destroy(); resolve({ valid: false, latencyMs: 10000, message: "Timed out" }); });
            req.on("error", e => resolve({ valid: false, latencyMs: Date.now() - started, message: e.message }));
            req.end();
        });
    }

    // Anthropic / Azure / OpenAI-compatible provider test (routed through built-in HTTP/SOCKS5 proxy if enabled)
    return new Promise((resolve) => {
        let u;
        try {
            const defBase = protocol === "anthropic-messages" ? "https://api.anthropic.com/v1" : baseURL;
            const b = defBase.endsWith("/") ? defBase : `${defBase}/`;
            u = new URL("models", b);
        } catch (e) {
            return resolve({ valid: false, latencyMs: 0, message: `Invalid baseURL: ${e.message}` });
        }
        const isHttp = u.protocol === "http:";
        const authHeaders = protocol === "anthropic-messages"
            ? { "x-api-key": apiKey, "anthropic-version": "2023-06-01" }
            : (protocol === "azure-openai" ? { "api-key": apiKey } : { "Authorization": `Bearer ${apiKey}` });
        const req = createProxiedRequest(!isHttp, {
            protocol: u.protocol,
            hostname: u.hostname,
            port: u.port || (isHttp ? 80 : 443),
            path: u.pathname + u.search,
            method: "GET",
            headers: {
                ...authHeaders,
                "User-Agent": "antigravity/2.32.1"
            },
            timeout: 10000
        }, (res) => {
            let raw = "";
            res.on("data", d => raw += d);
            res.on("end", () => {
                const ms = Date.now() - started;
                if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                    return resolve({ valid: true, latencyMs: ms, message: `Connected (${ms}ms · ${u.hostname})` });
                }
                if (res.statusCode === 404 && sampleModel) {
                    return resolve({ valid: true, latencyMs: ms, message: `Reachable (${ms}ms · ${u.hostname})` });
                }
                let msg = `HTTP ${res.statusCode}`;
                try { msg = JSON.parse(raw).error?.message || msg; } catch {}
                resolve({ valid: false, latencyMs: ms, message: msg });
            });
        });
        req.on("timeout", () => { req.destroy(); resolve({ valid: false, latencyMs: 10000, message: "Timed out" }); });
        req.on("error", e => resolve({ valid: false, latencyMs: Date.now() - started, message: e.message }));
        req.end();
    });
}

async function discoverProviderModelsLive(protocol, baseURL, apiKey) {
    if (!apiKey) throw new Error("Enter an API key first to fetch models.");
    if (protocol === "google-genai") {
        return new Promise((resolve, reject) => {
            const req = createProxiedRequest(true, {
                hostname: "generativelanguage.googleapis.com",
                port: 443,
                path: "/v1beta/models?pageSize=100",
                method: "GET",
                headers: { "x-goog-api-key": apiKey },
                timeout: 12000
            }, (res) => {
                let raw = "";
                res.on("data", d => raw += d);
                res.on("end", () => {
                    if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode} fetching models`));
                    try {
                        const j = JSON.parse(raw);
                        const list = (j.models || [])
                            .filter(m => (m.supportedGenerationMethods || []).includes("generateContent"))
                            .map(m => ({
                                id: String(m.name || "").replace(/^models\//, ""),
                                name: m.displayName || String(m.name || "").replace(/^models\//, ""),
                                context: Number(m.inputTokenLimit) || 1048576,
                                output: Number(m.outputTokenLimit) || 65536,
                                reasoning: !!m.thinking
                            }));
                        resolve(list);
                    } catch (e) {
                        reject(e);
                    }
                });
            });
            req.on("timeout", () => { req.destroy(); reject(new Error("Timed out")); });
            req.on("error", reject);
            req.end();
        });
    }

    return new Promise((resolve, reject) => {
        let u;
        try {
            const defBase = protocol === "anthropic-messages" ? (baseURL || "https://api.anthropic.com/v1") : baseURL;
            const b = defBase.endsWith("/") ? defBase : `${defBase}/`;
            u = new URL("models", b);
        } catch (e) {
            return reject(new Error(`Invalid Base URL: ${e.message}`));
        }
        const isHttp = u.protocol === "http:";
        const authHeaders = protocol === "anthropic-messages"
            ? { "x-api-key": apiKey, "anthropic-version": "2023-06-01" }
            : (protocol === "azure-openai" ? { "api-key": apiKey } : { "Authorization": `Bearer ${apiKey}` });
        const req = createProxiedRequest(!isHttp, {
            protocol: u.protocol,
            hostname: u.hostname,
            port: u.port || (isHttp ? 80 : 443),
            path: u.pathname + u.search,
            method: "GET",
            headers: {
                ...authHeaders,
                "User-Agent": "antigravity/2.32.1"
            },
            timeout: 12000
        }, (res) => {
            let raw = "";
            res.on("data", d => raw += d);
            res.on("end", () => {
                if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
                    let msg = `HTTP ${res.statusCode}`;
                    try { msg = JSON.parse(raw).error?.message || msg; } catch {}
                    return reject(new Error(msg));
                }
                try {
                    const j = JSON.parse(raw);
                    const arr = Array.isArray(j.data) ? j.data : (Array.isArray(j.models) ? j.models : []);
                    const list = arr.map(m => {
                        const mid = String(m.id || m.name || "").trim();
                        return {
                            id: mid,
                            name: String(m.display_name || m.name || mid),
                            context: Number(m.context_length || m.max_model_len || m.inputTokenLimit) || 200000,
                            output: Number(m.max_completion_tokens || m.outputTokenLimit) || 64000,
                            reasoning: true
                        };
                    }).filter(m => m.id);
                    resolve(list);
                } catch (e) {
                    reject(e);
                }
            });
        });
        req.on("timeout", () => { req.destroy(); reject(new Error("Timed out")); });
        req.on("error", reject);
        req.end();
    });
}

async function handleAgyConfigRequest(urlPath, req, res, rawBodyBuf) {
    const corsHeaders = {
        "Content-Type": "application/json; charset=UTF-8",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type"
    };
    if (req.method === "OPTIONS") {
        res.writeHead(204, corsHeaders);
        return res.end();
    }

    const buildSummary = () => {
        const rawText = readRawAgyConfigText();
        const parsed = loadParsedAgyConfig();
        const providersSummary = Object.entries(parsed.provider || {}).map(([pid, p]) => {
            const accounts = normalizeAccountsList(p?.options).map(acc => ({
                id: acc.id,
                name: acc.name,
                apiKey: acc.apiKey,
                maskedKey: acc.apiKey.length > 12 ? `${acc.apiKey.slice(0, 8)}••••••••${acc.apiKey.slice(-4)}` : "••••••••",
                active: !!acc.active,
                enabled: acc.enabled !== false
            }));
            const ks = extractApiKeysFromOptions(p?.options);
            const modelsMap = p?.models || {};
            const mKeys = Object.keys(modelsMap);
            const modelItems = mKeys.map(mk => ({
                id: mk,
                name: modelsMap[mk]?.name || mk,
                context: modelsMap[mk]?.limit?.context || 262144,
                output: modelsMap[mk]?.limit?.output || 32768,
                reasoning: modelsMap[mk]?.reasoning !== false
            }));
            return {
                id: pid,
                name: p?.name || pid,
                npm: p?.npm || (detectProviderProtocol(pid, p) === "google-genai" ? "@ai-sdk/google" : "@ai-sdk/openai-compatible"),
                protocol: detectProviderProtocol(pid, p),
                baseURL: p?.options?.baseURL || "",
                apiKey: ks[0] || "",
                accounts,
                modelCount: mKeys.length,
                models: mKeys,
                modelItems
            };
        });
        return {
            configPath: AGY_JSON_CONFIG_PATH,
            rawText,
            providers: providersSummary
        };
    };

    if (urlPath === "/__agy_config/get") {
        res.writeHead(200, corsHeaders);
        return res.end(JSON.stringify(buildSummary()));
    }

    let payload = {};
    try {
        payload = JSON.parse(rawBodyBuf.toString("utf8") || "{}");
    } catch {}

    if (urlPath === "/__agy_config/save" && req.method === "POST") {
        try {
            saveRawAgyConfigText(String(payload.rawText || ""));
            const synced = await syncAdminSettingsFiles(boundGatewayPort);
            res.writeHead(200, corsHeaders);
            return res.end(JSON.stringify({
                success: true,
                syncedModels: synced.models.list.length,
                ...buildSummary()
            }));
        } catch (err) {
            res.writeHead(400, corsHeaders);
            return res.end(JSON.stringify({ success: false, message: `JSON Error: ${err.message}` }));
        }
    }

    if (urlPath === "/__agy_config/discover_models" && req.method === "POST") {
        try {
            const npmStr = String(payload.npm || "").toLowerCase();
            if (npmStr.includes("anthropic")) {
                // Return curated Anthropic Claude catalog when using Anthropic protocol
                return res.writeHead(200, corsHeaders), res.end(JSON.stringify({
                    success: true,
                    models: [
                        { id: "claude-opus-4-6", name: "Claude Opus 4.6", context: 1000000, output: 128000, reasoning: true },
                        { id: "claude-sonnet-4-6", name: "Claude Sonnet 4.6", context: 1000000, output: 64000, reasoning: true },
                        { id: "claude-opus-4-5", name: "Claude Opus 4.5", context: 200000, output: 64000, reasoning: true },
                        { id: "claude-sonnet-4-5", name: "Claude Sonnet 4.5", context: 200000, output: 64000, reasoning: true },
                        { id: "claude-haiku-4-5", name: "Claude Haiku 4.5", context: 200000, output: 64000, reasoning: true }
                    ]
                }));
            }
            const proto = npmStr.includes("google") ? "google-genai" : "openai-compatible";
            const list = await discoverProviderModelsLive(proto, String(payload.baseURL || "").trim(), String(payload.apiKey || "").trim());
            res.writeHead(200, corsHeaders);
            return res.end(JSON.stringify({ success: true, models: list }));
        } catch (err) {
            res.writeHead(400, corsHeaders);
            return res.end(JSON.stringify({ success: false, message: err.message }));
        }
    }

    if (urlPath === "/__agy_config/test_draft" && req.method === "POST") {
        const npmStr = String(payload.npm || "").toLowerCase();
        const proto = npmStr.includes("google") ? "google-genai" : "openai-compatible";
        if (npmStr.includes("anthropic")) {
            return res.writeHead(200, corsHeaders), res.end(JSON.stringify({
                valid: !!String(payload.apiKey || "").trim(),
                latencyMs: 1,
                message: String(payload.apiKey || "").trim() ? "Anthropic configuration ready" : "API key is empty"
            }));
        }
        const check = await testProviderEndpointLive(proto, String(payload.baseURL || "").trim(), String(payload.apiKey || "").trim(), "test");
        res.writeHead(200, corsHeaders);
        return res.end(JSON.stringify(check));
    }

    const buildRichModelEntry = (m) => {
        const inputMods = Array.isArray(m.inputModalities) && m.inputModalities.length
            ? m.inputModalities
            : (m.attachment !== false ? ["text", "image"] : ["text"]);
        const outputMods = Array.isArray(m.outputModalities) && m.outputModalities.length
            ? m.outputModalities
            : ["text"];
        const entry = {
            name: String(m.name || m.id || "").trim(),
            limit: {
                context: Number(m.context) || 262144,
                output: Number(m.output) || 65536
            },
            attachment: inputMods.some(x => x !== "text"),
            reasoning: m.reasoning !== false,
            tool_call: m.tool_call !== false,
            temperature: m.temperature !== false,
            modalities: {
                input: inputMods,
                output: outputMods
            }
        };
        if (m.interleaved && m.interleaved !== "auto" && m.interleaved !== "none") {
            entry.interleaved = String(m.interleaved);
        }
        if (m.costInput !== undefined && m.costInput !== "" || m.costOutput !== undefined && m.costOutput !== "") {
            entry.cost = {
                input: Number(m.costInput) || 0,
                output: Number(m.costOutput) || 0,
                ...(m.costCacheRead !== undefined && m.costCacheRead !== "" ? { cache_read: Number(m.costCacheRead) || 0 } : {}),
                ...(m.costCacheWrite !== undefined && m.costCacheWrite !== "" ? { cache_write: Number(m.costCacheWrite) || 0 } : {})
            };
        }
        return entry;
    };

    if (urlPath === "/__agy_config/add_provider" && req.method === "POST") {
        try {
            const rawId = String(payload.id || "").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "-");
            const dispName = String(payload.name || rawId).trim();
            const npmPkg = String(payload.npm || "@ai-sdk/openai-compatible").trim();
            const baseURL = String(payload.baseURL || "").trim();
            const apiKey = String(payload.apiKey || "").trim();
            if (!rawId) throw new Error("Provider ID is required (e.g. openrouter, anthropic, logfare).");
            if (!npmPkg.includes("google") && !baseURL) throw new Error("Base URL is required.");

            let parsedHeaders = undefined;
            if (payload.customHeaders && String(payload.customHeaders).trim()) {
                try {
                    parsedHeaders = parseJsonc(String(payload.customHeaders));
                } catch (e) {
                    throw new Error(`Invalid Custom Headers JSON: ${e.message}`);
                }
            }

            const modelsInput = Array.isArray(payload.models) ? payload.models : [];
            const modelsObj = {};
            for (const m of modelsInput) {
                const mid = String(m.id || "").trim();
                if (!mid) continue;
                modelsObj[mid] = buildRichModelEntry(m);
            }

            const accountName = String(payload.accountName || "").trim() || "Account 1";
            const optionsObj = {
                ...(baseURL ? { baseURL } : {}),
                ...(apiKey ? {
                    apiKey,
                    accounts: [{
                        id: crypto.randomUUID(),
                        name: accountName,
                        apiKey,
                        active: true,
                        enabled: true
                    }]
                } : {}),
                ...(payload.setCacheKey ? { setCacheKey: true } : {}),
                ...(Number(payload.timeout) > 0 ? { timeout: Number(payload.timeout) } : {}),
                ...(parsedHeaders ? { headers: parsedHeaders } : {})
            };

            const current = loadParsedAgyConfig();
            current.provider = current.provider || {};
            current.provider[rawId] = {
                name: dispName,
                npm: npmPkg,
                options: optionsObj,
                models: modelsObj
            };

            saveRawAgyConfigText(JSON.stringify(current, null, 2));
            const synced = await syncAdminSettingsFiles(boundGatewayPort);
            res.writeHead(200, corsHeaders);
            return res.end(JSON.stringify({
                success: true,
                syncedModels: synced.models.list.length,
                ...buildSummary()
            }));
        } catch (err) {
            res.writeHead(400, corsHeaders);
            return res.end(JSON.stringify({ success: false, message: err.message }));
        }
    }

    if (urlPath === "/__agy_config/add_model" && req.method === "POST") {
        try {
            const pid = String(payload.providerId || "").trim();
            const mid = String(payload.modelId || payload.id || "").trim();
            if (!pid || !mid) throw new Error("Provider ID and Model ID are required.");
            const current = loadParsedAgyConfig();
            if (!current.provider?.[pid]) throw new Error(`Provider "${pid}" not found.`);
            current.provider[pid].models = current.provider[pid].models || {};
            current.provider[pid].models[mid] = buildRichModelEntry({ ...payload, id: mid });
            saveRawAgyConfigText(JSON.stringify(current, null, 2));
            const synced = await syncAdminSettingsFiles(boundGatewayPort);
            res.writeHead(200, corsHeaders);
            return res.end(JSON.stringify({
                success: true,
                syncedModels: synced.models.list.length,
                ...buildSummary()
            }));
        } catch (err) {
            res.writeHead(400, corsHeaders);
            return res.end(JSON.stringify({ success: false, message: err.message }));
        }
    }

    if (urlPath === "/__agy_config/delete_model" && req.method === "POST") {
        try {
            const pid = String(payload.providerId || "").trim();
            const mid = String(payload.modelId || "").trim();
            const current = loadParsedAgyConfig();
            if (current.provider?.[pid]?.models && mid in current.provider[pid].models) {
                delete current.provider[pid].models[mid];
            }
            saveRawAgyConfigText(JSON.stringify(current, null, 2));
            const synced = await syncAdminSettingsFiles(boundGatewayPort);
            res.writeHead(200, corsHeaders);
            return res.end(JSON.stringify({
                success: true,
                syncedModels: synced.models.list.length,
                ...buildSummary()
            }));
        } catch (err) {
            res.writeHead(400, corsHeaders);
            return res.end(JSON.stringify({ success: false, message: err.message }));
        }
    }

    const syncProviderAccountsOptions = (pObj, accountsList) => {
        pObj.options = pObj.options || {};
        if (accountsList.length > 0 && !accountsList.some(a => a.active)) {
            accountsList[0].active = true;
        }
        pObj.options.accounts = accountsList;
        const activeAcc = accountsList.find(a => a.active) || accountsList[0];
        pObj.options.apiKey = activeAcc ? activeAcc.apiKey : "";
        delete pObj.options.apiKeys;
    };

    if (urlPath === "/__agy_config/add_account" && req.method === "POST") {
        try {
            const pid = String(payload.providerId || "").trim();
            const accKey = String(payload.apiKey || "").trim();
            if (!pid || !accKey) throw new Error("Account API key is required.");
            const current = loadParsedAgyConfig();
            if (!current.provider?.[pid]) throw new Error(`Provider "${pid}" not found.`);
            const accounts = normalizeAccountsList(current.provider[pid].options);
            const accName = String(payload.name || "").trim() || `Account ${accounts.length + 1}`;
            const existing = accounts.find(a => a.apiKey === accKey);
            if (existing) {
                existing.name = accName;
                accounts.forEach(a => { a.active = (a.id === existing.id); });
            } else {
                accounts.forEach(a => { a.active = false; });
                accounts.push({
                    id: crypto.randomUUID(),
                    name: accName,
                    apiKey: accKey,
                    active: true,
                    enabled: true
                });
            }
            syncProviderAccountsOptions(current.provider[pid], accounts);
            saveRawAgyConfigText(JSON.stringify(current, null, 2));
            await syncAdminSettingsFiles(boundGatewayPort);
            res.writeHead(200, corsHeaders);
            return res.end(JSON.stringify({ success: true, ...buildSummary() }));
        } catch (err) {
            res.writeHead(400, corsHeaders);
            return res.end(JSON.stringify({ success: false, message: err.message }));
        }
    }

    if (urlPath === "/__agy_config/activate_account" && req.method === "POST") {
        try {
            const pid = String(payload.providerId || "").trim();
            const accId = String(payload.accountId || "").trim();
            const current = loadParsedAgyConfig();
            if (!current.provider?.[pid]) throw new Error(`Provider "${pid}" not found.`);
            const accounts = normalizeAccountsList(current.provider[pid].options);
            accounts.forEach(a => { a.active = (a.id === accId); });
            syncProviderAccountsOptions(current.provider[pid], accounts);
            saveRawAgyConfigText(JSON.stringify(current, null, 2));
            await syncAdminSettingsFiles(boundGatewayPort);
            res.writeHead(200, corsHeaders);
            return res.end(JSON.stringify({ success: true, ...buildSummary() }));
        } catch (err) {
            res.writeHead(400, corsHeaders);
            return res.end(JSON.stringify({ success: false, message: err.message }));
        }
    }

    if (urlPath === "/__agy_config/delete_account" && req.method === "POST") {
        try {
            const pid = String(payload.providerId || "").trim();
            const accId = String(payload.accountId || "").trim();
            const current = loadParsedAgyConfig();
            if (!current.provider?.[pid]) throw new Error(`Provider "${pid}" not found.`);
            const accounts = normalizeAccountsList(current.provider[pid].options).filter(a => a.id !== accId);
            syncProviderAccountsOptions(current.provider[pid], accounts);
            saveRawAgyConfigText(JSON.stringify(current, null, 2));
            await syncAdminSettingsFiles(boundGatewayPort);
            res.writeHead(200, corsHeaders);
            return res.end(JSON.stringify({ success: true, ...buildSummary() }));
        } catch (err) {
            res.writeHead(400, corsHeaders);
            return res.end(JSON.stringify({ success: false, message: err.message }));
        }
    }

    if (urlPath === "/__agy_config/test_account" && req.method === "POST") {
        const pid = String(payload.providerId || "").trim();
        const accId = String(payload.accountId || "").trim();
        const current = loadParsedAgyConfig();
        const p = current.provider?.[pid];
        if (!p) {
            res.writeHead(404, corsHeaders);
            return res.end(JSON.stringify({ valid: false, message: "Provider not found." }));
        }
        const accounts = normalizeAccountsList(p.options);
        const target = accounts.find(a => a.id === accId);
        if (!target) {
            res.writeHead(404, corsHeaders);
            return res.end(JSON.stringify({ valid: false, message: "Account not found." }));
        }
        const proto = detectProviderProtocol(pid, p);
        if (proto === "anthropic-messages") {
            return res.writeHead(200, corsHeaders), res.end(JSON.stringify({ valid: true, latencyMs: 1, message: "Anthropic API key ready" }));
        }
        const sampleModel = Object.keys(p.models || {})[0] || "";
        const check = await testProviderEndpointLive(proto, p.options?.baseURL || "", target.apiKey, sampleModel);
        res.writeHead(200, corsHeaders);
        return res.end(JSON.stringify(check));
    }

    if (urlPath === "/__agy_config/update_key" && req.method === "POST") {
        try {
            const pid = String(payload.providerId || "").trim();
            const newKey = String(payload.apiKey || "").trim();
            const current = loadParsedAgyConfig();
            if (!current.provider?.[pid]) {
                throw new Error(`Provider "${pid}" not found.`);
            }
            current.provider[pid].options = current.provider[pid].options || {};
            current.provider[pid].options.apiKey = newKey;
            saveRawAgyConfigText(JSON.stringify(current, null, 2));
            await syncAdminSettingsFiles(boundGatewayPort);
            res.writeHead(200, corsHeaders);
            return res.end(JSON.stringify({ success: true, ...buildSummary() }));
        } catch (err) {
            res.writeHead(400, corsHeaders);
            return res.end(JSON.stringify({ success: false, message: err.message }));
        }
    }

    if (urlPath === "/__agy_config/delete_provider" && req.method === "POST") {
        try {
            const pid = String(payload.providerId || "").trim();
            const current = loadParsedAgyConfig();
            if (current.provider && pid in current.provider) {
                delete current.provider[pid];
            }
            saveRawAgyConfigText(JSON.stringify(current, null, 2));
            const synced = await syncAdminSettingsFiles(boundGatewayPort);
            res.writeHead(200, corsHeaders);
            return res.end(JSON.stringify({
                success: true,
                syncedModels: synced.models.list.length,
                ...buildSummary()
            }));
        } catch (err) {
            res.writeHead(400, corsHeaders);
            return res.end(JSON.stringify({ success: false, message: err.message }));
        }
    }

    if (urlPath === "/__agy_config/test_provider" && req.method === "POST") {
        const pid = String(payload.providerId || "").trim();
        const current = loadParsedAgyConfig();
        const p = current.provider?.[pid];
        if (!p) {
            res.writeHead(404, corsHeaders);
            return res.end(JSON.stringify({ valid: false, message: "Provider not found." }));
        }
        const proto = detectProviderProtocol(pid, p);
        const ks = extractApiKeysFromOptions(p.options);
        const sampleModel = Object.keys(p.models || {})[0] || "";
        const check = await testProviderEndpointLive(proto, p.options?.baseURL || "", ks[0] || "", sampleModel);
        res.writeHead(200, corsHeaders);
        return res.end(JSON.stringify(check));
    }

    res.writeHead(404, corsHeaders);
    res.end(JSON.stringify({ error: "Not found" }));
}

// ---------------------------------------------------------------------------
// Native Plugin Catalog, Rich Marketplace & ZIP Installer (71 Plugins)
// ---------------------------------------------------------------------------
const pluginPreviewCache = new Map();

function inspectPluginZipBufferForPreview(zipBuf) {
    const result = { readme: "", skills: [], mcpServers: [] };
    try {
        let eocdOffset = -1;
        const minOffset = Math.max(0, zipBuf.length - 65557);
        for (let i = zipBuf.length - 22; i >= minOffset; i--) {
            if (zipBuf.readUInt32LE(i) === 0x06054b50) { eocdOffset = i; break; }
        }
        if (eocdOffset < 0) return result;
        const totalEntries = zipBuf.readUInt16LE(eocdOffset + 10);
        let ptr = zipBuf.readUInt32LE(eocdOffset + 16);

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

            const isReadme = /^([^/]+\/)?readme\.md$/i.test(rawName);
            const isSkill = /(?:^|\/)skills\/([^/]+)\/SKILL\.md$/i.test(rawName);
            const isMcp = /(?:^|\/)mcp_config\.json$/i.test(rawName);
            if (!isReadme && !isSkill && !isMcp) continue;

            if (localHeaderOffset + 30 > zipBuf.length || zipBuf.readUInt32LE(localHeaderOffset) !== 0x04034b50) continue;
            if (method !== 0 && method !== 8) continue;
            const lNameLen = zipBuf.readUInt16LE(localHeaderOffset + 26);
            const lExtraLen = zipBuf.readUInt16LE(localHeaderOffset + 28);
            const dataStart = localHeaderOffset + 30 + lNameLen + lExtraLen;
            const compSlice = zipBuf.slice(dataStart, dataStart + compSize);
            const text = (method === 0 ? compSlice : zlib.inflateRawSync(compSlice)).toString("utf8");

            if (isReadme && !result.readme) {
                result.readme = text;
            } else if (isSkill) {
                const skillMatch = /(?:^|\/)skills\/([^/]+)\/SKILL\.md$/i.exec(rawName);
                let sName = skillMatch ? skillMatch[1] : "skill";
                let sDesc = "";
                const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
                if (fm) {
                    const nm = /^name:\s*(.+)$/m.exec(fm[1]);
                    const ds = /^description:\s*(.+)$/m.exec(fm[1]);
                    if (nm) sName = nm[1].trim().replace(/^["']|["']$/g, "");
                    if (ds) sDesc = ds[1].trim().replace(/^["']|["']$/g, "");
                }
                result.skills.push({ name: sName, description: sDesc, content: text });
            } else if (isMcp) {
                try {
                    const mj = JSON.parse(text);
                    const servers = mj.mcpServers || mj.servers || {};
                    for (const sKey of Object.keys(servers)) {
                        result.mcpServers.push({ name: sKey });
                    }
                } catch {}
            }
        }
    } catch {}
    return result;
}

function loadPluginCatalogEntries() {
    const map = new Map();
    for (const srcInfo of MARKETPLACE_CACHE_FILES) {
        try {
            if (!fs.existsSync(srcInfo.filePath)) continue;
            const parsed = JSON.parse(fs.readFileSync(srcInfo.filePath, "utf8"));
            const items = Array.isArray(parsed.plugins) ? parsed.plugins : [];
            for (const p of items) {
                const uid = String(p.name || "").trim();
                const archiveUrl = p.source && p.source.url ? String(p.source.url) : "";
                if (!uid || !archiveUrl || map.has(uid)) continue;
                map.set(uid, {
                    uid,
                    marketplace: srcInfo.marketplace,
                    groupTitle: srcInfo.groupTitle,
                    groupDesc: srcInfo.groupDesc,
                    name: p.displayName || uid,
                    description: p.description || "",
                    version: p.version || "1.0.0",
                    logo: p.logo || "",
                    author: p.author || null,
                    homepage: p.homepage || "",
                    repository: typeof p.repository === "string" ? p.repository : ((p.repository && p.repository.url) || ""),
                    keywords: Array.isArray(p.keywords) ? p.keywords : [],
                    suggestedPrompts: Array.isArray(p.suggestedPrompts) ? p.suggestedPrompts : [],
                    archiveUrl,
                    sha256: (p.source && p.source.sha256) || "",
                    rawMeta: p
                });
            }
        } catch {}
    }
    return map;
}

function toMarketplaceCustomizationProto(item) {
    const authorObj = item.author
        ? (typeof item.author === "string"
            ? { name: item.author, email: "", url: "" }
            : { name: item.author.name || "", email: item.author.email || "", url: item.author.url || "" })
        : { name: "Google / Partner", email: "", url: "" };

    return {
        marketplace: item.marketplace,
        id: item.uid,
        displayName: item.name,
        description: item.description,
        logo: item.logo || "",
        version: item.version || "1.0.0",
        author: authorObj,
        homepage: item.homepage || "",
        repository: item.repository || "",
        source: {
            source: {
                case: "archive",
                value: { url: item.archiveUrl, sha256: item.sha256 }
            }
        },
        kind: { case: "plugin", value: {} }
    };
}

function getInstalledPluginUids() {
    const installed = [];
    try {
        if (fs.existsSync(PLUGINS_INSTALL_ROOT)) {
            for (const ent of fs.readdirSync(PLUGINS_INSTALL_ROOT, { withFileTypes: true })) {
                if (!ent.isDirectory()) continue;
                if (fs.existsSync(path.join(PLUGINS_INSTALL_ROOT, ent.name, "plugin.json"))) {
                    installed.push(ent.name);
                }
            }
        }
    } catch {}
    return installed;
}

function removePluginDirSafe(targetDir) {
    if (!fs.existsSync(targetDir)) return;
    for (const ent of fs.readdirSync(targetDir, { withFileTypes: true })) {
        const child = path.join(targetDir, ent.name);
        if (ent.isDirectory()) {
            removePluginDirSafe(child);
        } else {
            try { fs.chmodSync(child, 0o666); } catch {}
            fs.unlinkSync(child);
        }
    }
    try { fs.rmdirSync(targetDir); } catch {}
}

function downloadHttpsBuffer(urlStr, maxRedirects = 5) {
    return downloadBufferWithProxy(urlStr, maxRedirects);
}

function extractZipBufferToDir(zipBuf, destDir) {
    let eocdOffset = -1;
    const minOffset = Math.max(0, zipBuf.length - 65557);
    for (let i = zipBuf.length - 22; i >= minOffset; i--) {
        if (zipBuf.readUInt32LE(i) === 0x06054b50) {
            eocdOffset = i;
            break;
        }
    }
    if (eocdOffset < 0) throw new Error("Invalid plugin ZIP archive");

    const totalEntries = zipBuf.readUInt16LE(eocdOffset + 10);
    const cdOffset = zipBuf.readUInt32LE(eocdOffset + 16);
    const resolvedRoot = path.resolve(destDir);
    fs.mkdirSync(resolvedRoot, { recursive: true });

    let ptr = cdOffset;
    for (let i = 0; i < totalEntries; i++) {
        if (ptr + 46 > zipBuf.length || zipBuf.readUInt32LE(ptr) !== 0x02014b50) break;
        const method = zipBuf.readUInt16LE(ptr + 10);
        const compSize = zipBuf.readUInt32LE(ptr + 20);
        const nameLen = zipBuf.readUInt16LE(ptr + 28);
        const extraLen = zipBuf.readUInt16LE(ptr + 30);
        const commentLen = zipBuf.readUInt16LE(ptr + 32);
        const localHeaderOffset = zipBuf.readUInt32LE(ptr + 42);

        const rawName = zipBuf.slice(ptr + 46, ptr + 46 + nameLen).toString("utf8");
        ptr += 46 + nameLen + extraLen + commentLen;

        const cleanRel = rawName.replace(/\\/g, "/").replace(/^\/+/, "");
        if (!cleanRel) continue;
        const targetPath = path.resolve(resolvedRoot, cleanRel);
        if (targetPath !== resolvedRoot && !targetPath.startsWith(resolvedRoot + path.sep)) continue;

        if (cleanRel.endsWith("/")) {
            fs.mkdirSync(targetPath, { recursive: true });
            continue;
        }
        if (localHeaderOffset + 30 > zipBuf.length || zipBuf.readUInt32LE(localHeaderOffset) !== 0x04034b50) {
            throw new Error(`Corrupt local header for ${cleanRel}`);
        }
        const lNameLen = zipBuf.readUInt16LE(localHeaderOffset + 26);
        const lExtraLen = zipBuf.readUInt16LE(localHeaderOffset + 28);
        const dataStart = localHeaderOffset + 30 + lNameLen + lExtraLen;
        const compSlice = zipBuf.slice(dataStart, dataStart + compSize);

        const fileBytes = method === 0 ? compSlice : zlib.inflateRawSync(compSlice);
        fs.mkdirSync(path.dirname(targetPath), { recursive: true });
        fs.writeFileSync(targetPath, fileBytes);
    }
}

async function handlePluginManagerRequest(urlPath, req, res, rawBodyBuf) {
    const corsHeaders = {
        "Content-Type": "application/json; charset=UTF-8",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type"
    };
    if (req.method === "OPTIONS") {
        res.writeHead(204, corsHeaders);
        return res.end();
    }

    const catalog = loadPluginCatalogEntries();
    const allItems = Array.from(catalog.values());

    if (urlPath === "/__agy_plugins/list") {
        const installedUids = getInstalledPluginUids();
        const plugins = allItems.map((item) => ({
            plugin: { uid: item.uid, name: item.name, description: item.description }
        }));
        res.writeHead(200, corsHeaders);
        return res.end(JSON.stringify({ plugins, installedUids }));
    }

    if (urlPath === "/__agy_plugins/marketplace_search") {
        let query = "";
        let groupId = "";
        try {
            const p = JSON.parse(rawBodyBuf.toString("utf8") || "{}");
            query = String(p.query || "").trim().toLowerCase();
            groupId = String(p.groupId || "").trim();
        } catch {}

        let filtered = allItems;
        if (groupId) filtered = filtered.filter(it => it.marketplace === groupId);
        if (query) {
            filtered = filtered.filter(it =>
                it.uid.toLowerCase().includes(query) ||
                it.name.toLowerCase().includes(query) ||
                it.description.toLowerCase().includes(query) ||
                it.keywords.some(k => String(k).toLowerCase().includes(query))
            );
        }

        const customizations = filtered.map(toMarketplaceCustomizationProto);
        const groups = [];
        if (!query && !groupId) {
            for (const srcInfo of MARKETPLACE_CACHE_FILES) {
                const memberIds = filtered.filter(it => it.marketplace === srcInfo.marketplace).map(it => it.uid);
                if (memberIds.length > 0) {
                    groups.push({
                        id: srcInfo.marketplace,
                        displayName: srcInfo.groupTitle,
                        description: srcInfo.groupDesc,
                        memberIds,
                        nextPageToken: ""
                    });
                }
            }
        }
        res.writeHead(200, corsHeaders);
        return res.end(JSON.stringify({ customizations, groups, nextPageToken: "" }));
    }

    if (urlPath === "/__agy_plugins/marketplace_featured") {
        const officialSpotlight = ["firebase", "flutter", "gemini-api", "gdrive", "chrome-devtools-plugin", "google-cloud-developer"]
            .filter(id => catalog.has(id));
        const partnerSpotlight = ["context7", "figma", "stripe", "notion", "linear", "railway"]
            .filter(id => catalog.has(id));

        const featured = [];
        if (officialSpotlight.length > 0) {
            featured.push({
                id: "featured-google",
                eyebrow: "Built by Google",
                displayName: "Essential Google Developer Plugins",
                description: "Supercharge Antigravity with Firebase, Flutter, Gemini API, Chrome DevTools, and Workspace integrations.",
                memberIds: officialSpotlight
            });
        }
        if (partnerSpotlight.length > 0) {
            featured.push({
                id: "featured-partners",
                eyebrow: "Featured Partners",
                displayName: "Top Ecosystem Integrations",
                description: "Connect live docs, design systems, payments, and cloud deployments in one click.",
                memberIds: partnerSpotlight
            });
        }
        const customizations = [...officialSpotlight, ...partnerSpotlight]
            .map(id => catalog.get(id))
            .filter(Boolean)
            .map(toMarketplaceCustomizationProto);

        res.writeHead(200, corsHeaders);
        return res.end(JSON.stringify({ featured, customizations }));
    }

    if (urlPath === "/__agy_plugins/marketplace_item") {
        let id = "";
        try {
            const p = JSON.parse(rawBodyBuf.toString("utf8") || "{}");
            id = String(p.id || "").trim();
            if (id.includes("/")) id = id.split("/").pop();
        } catch {}
        const item = catalog.get(id);
        if (!item) {
            res.writeHead(404, corsHeaders);
            return res.end(JSON.stringify({ error: "Plugin not found" }));
        }
        const customization = toMarketplaceCustomizationProto(item);
        let previewMeta = pluginPreviewCache.get(item.uid);
        if (!previewMeta) {
            const targetDir = path.join(PLUGINS_INSTALL_ROOT, item.uid);
            const rPath = path.join(targetDir, "README.md");
            if (fs.existsSync(rPath)) {
                previewMeta = { readme: fs.readFileSync(rPath, "utf8"), skills: [], mcpServers: [] };
            } else {
                try {
                    const zipBuf = await downloadHttpsBuffer(item.archiveUrl);
                    previewMeta = inspectPluginZipBufferForPreview(zipBuf);
                } catch {
                    previewMeta = { readme: "", skills: [], mcpServers: [] };
                }
            }
            pluginPreviewCache.set(item.uid, previewMeta);
        }

        const authorObj = item.author
            ? (typeof item.author === "string"
                ? { name: item.author, email: "", url: "" }
                : { name: item.author.name || "", email: item.author.email || "", url: item.author.url || "" })
            : { name: "Google / Partner", email: "", url: "" };

        const pluginValue = {
            name: item.uid,
            displayName: item.name,
            description: item.description,
            version: item.version,
            logo: item.logo,
            path: "",
            hooksJson: "",
            author: authorObj,
            homepage: item.homepage,
            repository: item.repository,
            keywords: item.keywords || [],
            suggestedPrompts: item.suggestedPrompts || [],
            readme: previewMeta.readme || `# ${item.name}\n\n${item.description}`,
            skills: previewMeta.skills || [],
            agents: [],
            rules: [],
            mcpServers: previewMeta.mcpServers || [],
            sidecars: [],
            themes: []
        };

        res.writeHead(200, corsHeaders);
        return res.end(JSON.stringify({
            customization,
            preview: {
                case: "plugin",
                value: pluginValue
            }
        }));
    }

    if (urlPath === "/__agy_plugins/install" && req.method === "POST") {
        try {
            const payload = JSON.parse(rawBodyBuf.toString("utf8") || "{}");
            let uid = String(payload.uid || payload.id || "").trim();
            if (uid.includes("/")) uid = uid.split("/").pop();
            if (!/^[a-zA-Z0-9._-]+$/.test(uid)) throw new Error("Invalid plugin identifier");
            const entry = catalog.get(uid);
            if (!entry) throw new Error(`Plugin "${uid}" was not found`);

            const zipBuf = await downloadHttpsBuffer(entry.archiveUrl);
            const targetDir = path.join(PLUGINS_INSTALL_ROOT, uid);
            removePluginDirSafe(targetDir);
            extractZipBufferToDir(zipBuf, targetDir);

            const manifestPath = path.join(targetDir, "plugin.json");
            if (!fs.existsSync(manifestPath)) {
                const children = fs.readdirSync(targetDir, { withFileTypes: true });
                if (children.length === 1 && children[0].isDirectory()) {
                    const nestedDir = path.join(targetDir, children[0].name);
                    for (const sub of fs.readdirSync(nestedDir)) {
                        fs.renameSync(path.join(nestedDir, sub), path.join(targetDir, sub));
                    }
                    fs.rmSync(nestedDir, { recursive: true, force: true });
                }
            }
            if (!fs.existsSync(manifestPath)) {
                fs.writeFileSync(manifestPath, JSON.stringify({
                    name: entry.uid,
                    displayName: entry.name,
                    version: entry.version,
                    description: entry.description
                }, null, 2), "utf8");
            }

            if (_lsHotRestartCallback) {
                try { await _lsHotRestartCallback(); } catch {}
            }

            res.writeHead(200, corsHeaders);
            return res.end(JSON.stringify({ success: true, message: `Installed ${entry.name}`, installedPaths: [targetDir] }));
        } catch (err) {
            res.writeHead(500, corsHeaders);
            return res.end(JSON.stringify({ success: false, message: err.message }));
        }
    }

    if (urlPath === "/__agy_plugins/install_github" && req.method === "POST") {
        try {
            const payload = JSON.parse(rawBodyBuf.toString("utf8") || "{}");
            const ghRes = await installPluginFromGitHubUrl(String(payload.url || ""), PLUGINS_INSTALL_ROOT);
            if (_lsHotRestartCallback) {
                try { await _lsHotRestartCallback(); } catch {}
            }
            res.writeHead(200, corsHeaders);
            return res.end(JSON.stringify({
                success: true,
                pluginId: ghRes.pluginId,
                displayName: ghRes.displayName,
                filesExtracted: ghRes.filesExtracted,
                message: `Installed "${ghRes.displayName}" (${ghRes.filesExtracted} files)`
            }));
        } catch (err) {
            res.writeHead(400, corsHeaders);
            return res.end(JSON.stringify({ success: false, message: err.message }));
        }
    }

    if (urlPath === "/__agy_plugins/delete" && req.method === "POST") {
        try {
            const payload = JSON.parse(rawBodyBuf.toString("utf8") || "{}");
            const uid = String(payload.pluginId || payload.uid || "").trim();
            if (!/^[a-zA-Z0-9._-]+$/.test(uid)) throw new Error("Invalid plugin identifier");
            removePluginDirSafe(path.join(PLUGINS_INSTALL_ROOT, uid));
            if (_lsHotRestartCallback) {
                try { await _lsHotRestartCallback(); } catch {}
            }
            res.writeHead(200, corsHeaders);
            return res.end(JSON.stringify({ success: true }));
        } catch (err) {
            res.writeHead(500, corsHeaders);
            return res.end(JSON.stringify({ success: false, message: err.message }));
        }
    }

    res.writeHead(404, corsHeaders);
    res.end(JSON.stringify({ error: "Not found" }));
}

// ---------------------------------------------------------------------------
// Native React Screen: 'Settings -> API Key & Account' (Visual + JSONC Editor)
// ---------------------------------------------------------------------------
function buildProvidersJsonScreenCode(gwBase, syms = {}) {
    const R = syms.reactSym || "A";
    const UP = syms.pageHeaderSym || "UP";
    const YP = syms.sectionCardSym || "YP";
    const WP = syms.cardContainerSym || "WP";
    const XP = syms.cardRowSym || "XP";
    const BTN = syms.btnSym || "aB";
    const ICON = syms.iconSym || "lt";
    const bindLocalSyms = `var {A,UP,YP,WP,XP,aB,lt}=_agyGetUiSyms();`;
    return `function _agyGetUiSyms(){return{A:${R},UP:${UP},YP:${YP},WP:${WP},XP:${XP},aB:${BTN},lt:${ICON}}}
var _agyModelCtxMap={};
var _agyTelemetryState={isStreaming:!1,totalRequests:0,totalPromptTokens:0,totalCompletionTokens:0,totalCostUsd:0,lastTokPerSec:0,avgTokPerSec:0,lastTtftMs:0,lastModel:""};
var _agyTelListeners=new Set();
var _agyActiveModelHint="";
var _agyOAuthStream={startMs:0,firstMs:0,chars:0,lastTickMs:0};
function _agyEmitTel(patch){
  Object.assign(_agyTelemetryState,patch);
  var snap={..._agyTelemetryState};
  _agyTelListeners.forEach(fn=>{try{fn(snap)}catch{}});
}
var _AGY_PROVIDER_PRESETS=[
  {preset:"openai",id:"openai",name:"OpenAI",npm:"@ai-sdk/openai",baseURL:"https://api.openai.com/v1"},
  {preset:"anthropic",id:"anthropic",name:"Anthropic (Claude)",npm:"@ai-sdk/anthropic",baseURL:"https://api.anthropic.com/v1"},
  {preset:"google",id:"google",name:"Google Gemini",npm:"@ai-sdk/google",baseURL:"https://generativelanguage.googleapis.com/v1beta"},
  {preset:"openrouter",id:"openrouter",name:"OpenRouter",npm:"@ai-sdk/openrouter",baseURL:"https://openrouter.ai/api/v1"},
  {preset:"deepseek",id:"deepseek",name:"DeepSeek",npm:"@ai-sdk/deepseek",baseURL:"https://api.deepseek.com/v1"},
  {preset:"xai",id:"xai",name:"xAI (Grok)",npm:"@ai-sdk/xai",baseURL:"https://api.x.ai/v1"},
  {preset:"groq",id:"groq",name:"Groq",npm:"@ai-sdk/groq",baseURL:"https://api.groq.com/openai/v1"},
  {preset:"mistral",id:"mistral",name:"Mistral AI",npm:"@ai-sdk/mistral",baseURL:"https://api.mistral.ai/v1"},
  {preset:"together",id:"together",name:"Together AI",npm:"@ai-sdk/togetherai",baseURL:"https://api.together.xyz/v1"},
  {preset:"fireworks",id:"fireworks",name:"Fireworks AI",npm:"@ai-sdk/fireworks",baseURL:"https://api.fireworks.ai/inference/v1"},
  {preset:"cerebras",id:"cerebras",name:"Cerebras",npm:"@ai-sdk/cerebras",baseURL:"https://api.cerebras.ai/v1"},
  {preset:"perplexity",id:"perplexity",name:"Perplexity",npm:"@ai-sdk/perplexity",baseURL:"https://api.perplexity.ai"},
  {preset:"alibaba",id:"alibaba",name:"Alibaba Qwen (DashScope)",npm:"@ai-sdk/alibaba",baseURL:"https://dashscope-intl.aliyuncs.com/compatible-mode/v1"},
  {preset:"zhipu",id:"zhipu",name:"Zhipu GLM (Z.ai)",npm:"@ai-sdk/openai-compatible",baseURL:"https://api.z.ai/api/paas/v4"},
  {preset:"moonshot",id:"moonshot",name:"Moonshot AI (Kimi)",npm:"@ai-sdk/openai-compatible",baseURL:"https://api.moonshot.ai/v1"},
  {preset:"minimax",id:"minimax",name:"MiniMax",npm:"@ai-sdk/openai-compatible",baseURL:"https://api.minimax.io/v1"},
  {preset:"cohere",id:"cohere",name:"Cohere",npm:"@ai-sdk/cohere",baseURL:"https://api.cohere.ai/compatibility/v1"},
  {preset:"nvidia",id:"nvidia",name:"NVIDIA NIM",npm:"@ai-sdk/openai-compatible",baseURL:"https://integrate.api.nvidia.com/v1"},
  {preset:"huggingface",id:"huggingface",name:"HuggingFace Router",npm:"@ai-sdk/openai-compatible",baseURL:"https://router.huggingface.co/v1"},
  {preset:"logfare",id:"logfare",name:"Logfare",npm:"@ai-sdk/openai-compatible",baseURL:"https://logfare.ai/v1"},
  {preset:"ollama",id:"ollama",name:"Ollama (Local)",npm:"@ai-sdk/openai-compatible",baseURL:"http://127.0.0.1:11434/v1"},
  {preset:"lmstudio",id:"lmstudio",name:"LM Studio (Local)",npm:"@ai-sdk/openai-compatible",baseURL:"http://127.0.0.1:1234/v1"},
  {preset:"vllm",id:"vllm",name:"vLLM / SGLang (Local)",npm:"@ai-sdk/openai-compatible",baseURL:"http://127.0.0.1:8000/v1"},
  {preset:"azure",id:"azure",name:"Azure OpenAI",npm:"@ai-sdk/azure",baseURL:"https://YOUR_RESOURCE.openai.azure.com/openai/deployments/YOUR_DEPLOYMENT"},
  {preset:"custom-oai",id:"",name:"",npm:"@ai-sdk/openai-compatible",baseURL:""},
  {preset:"custom-anth",id:"",name:"",npm:"@ai-sdk/anthropic",baseURL:"https://api.anthropic.com/v1"}
];
var _AGY_SDK_OPTIONS=[
  {value:"@ai-sdk/openai-compatible",label:"OpenAI-Compatible (/chat/completions)"},
  {value:"@ai-sdk/openai",label:"OpenAI Official (@ai-sdk/openai)"},
  {value:"@ai-sdk/anthropic",label:"Anthropic Messages (/v1/messages)"},
  {value:"@ai-sdk/google",label:"Google GenAI (/v1beta/models)"},
  {value:"@ai-sdk/openrouter",label:"OpenRouter (@ai-sdk/openrouter)"},
  {value:"@ai-sdk/deepseek",label:"DeepSeek (@ai-sdk/deepseek)"},
  {value:"@ai-sdk/xai",label:"xAI Grok (@ai-sdk/xai)"},
  {value:"@ai-sdk/groq",label:"Groq (@ai-sdk/groq)"},
  {value:"@ai-sdk/mistral",label:"Mistral (@ai-sdk/mistral)"},
  {value:"@ai-sdk/togetherai",label:"Together AI (@ai-sdk/togetherai)"},
  {value:"@ai-sdk/fireworks",label:"Fireworks AI (@ai-sdk/fireworks)"},
  {value:"@ai-sdk/cerebras",label:"Cerebras (@ai-sdk/cerebras)"},
  {value:"@ai-sdk/perplexity",label:"Perplexity (@ai-sdk/perplexity)"},
  {value:"@ai-sdk/alibaba",label:"Alibaba DashScope (@ai-sdk/alibaba)"},
  {value:"@ai-sdk/cohere",label:"Cohere (@ai-sdk/cohere)"},
  {value:"@ai-sdk/azure",label:"Azure OpenAI (@ai-sdk/azure)"}
];
function _makeEmptyModelDraft(){
  return {
    id:"",name:"",context:"262144",output:"65536",
    reasoning:!0,tool_call:!0,temperature:!0,
    interleaved:"auto",
    inputModalities:["text","image"],
    costInput:"",costOutput:"",costCacheRead:"",costCacheWrite:"",
    showCost:!1
  };
}
function _AgyModelFormFields({draft,setDraft,onSubmit,onCancel,submitLabel,busy,inputCls}){
  ${bindLocalSyms}
  var toggleMod=mod=>{
    setDraft(d=>{
      var cur=Array.isArray(d.inputModalities)?d.inputModalities:["text"];
      var next=cur.includes(mod)?cur.filter(x=>x!==mod):[...cur,mod];
      if(!next.includes("text"))next.unshift("text");
      return {...d,inputModalities:next};
    });
  };
  return A.createElement("div",{className:"p-3 rounded-xl bg-muted/40 border border-border flex flex-col gap-2.5"},
    A.createElement("div",{className:"grid grid-cols-1 sm:grid-cols-2 gap-2"},
      A.createElement("input",{type:"text",placeholder:"Model ID (e.g. claude-sonnet-4-6, qwen-3.8-27b)",value:draft.id,onChange:e=>setDraft(d=>({...d,id:e.target.value})),className:inputCls+" font-mono"}),
      A.createElement("input",{type:"text",placeholder:"Display Name (optional)",value:draft.name,onChange:e=>setDraft(d=>({...d,name:e.target.value})),className:inputCls})
    ),
    A.createElement("div",{className:"grid grid-cols-2 sm:grid-cols-3 gap-2 items-center"},
      A.createElement("div",{className:"flex flex-col gap-1"},
        A.createElement("span",{className:"text-[10px] text-muted-foreground"},"Context Window Tokens"),
        A.createElement("input",{type:"number",placeholder:"Context (262144)",value:draft.context,onChange:e=>setDraft(d=>({...d,context:e.target.value})),className:inputCls+" font-mono"})
      ),
      A.createElement("div",{className:"flex flex-col gap-1"},
        A.createElement("span",{className:"text-[10px] text-muted-foreground"},"Max Output Tokens"),
        A.createElement("input",{type:"number",placeholder:"Max Output (65536)",value:draft.output,onChange:e=>setDraft(d=>({...d,output:e.target.value})),className:inputCls+" font-mono"})
      ),
      A.createElement("div",{className:"col-span-2 sm:col-span-1 flex flex-col gap-1"},
        A.createElement("span",{className:"text-[10px] text-muted-foreground"},"Quick Context Presets"),
        A.createElement("div",{className:"flex items-center gap-1"},
          [["128K","131072"],["256K","262144"],["1M","1048576"],["2M","2097152"]].map(([lbl,val])=>A.createElement("button",{
            key:lbl,type:"button",
            onClick:()=>setDraft(d=>({...d,context:val})),
            className:"px-2 py-1 rounded text-[11px] border border-border cursor-pointer "+(String(draft.context)===val?"bg-primary text-primary-foreground":"bg-secondary text-secondary-foreground hover:opacity-90")
          },lbl))
        )
      )
    ),
    A.createElement("div",{className:"flex flex-wrap items-center gap-4 pt-0.5 text-xs text-foreground"},
      A.createElement("label",{className:"flex items-center gap-1.5 cursor-pointer"},
        A.createElement("input",{type:"checkbox",checked:draft.reasoning,onChange:e=>setDraft(d=>({...d,reasoning:e.target.checked}))}),"Reasoning / Thinking"
      ),
      A.createElement("label",{className:"flex items-center gap-1.5 cursor-pointer"},
        A.createElement("input",{type:"checkbox",checked:draft.tool_call,onChange:e=>setDraft(d=>({...d,tool_call:e.target.checked}))}),"Tool Calling"
      ),
      A.createElement("label",{className:"flex items-center gap-1.5 cursor-pointer"},
        A.createElement("input",{type:"checkbox",checked:draft.temperature,onChange:e=>setDraft(d=>({...d,temperature:e.target.checked}))}),"Temperature"
      ),
      draft.reasoning&&A.createElement("div",{className:"flex items-center gap-1.5"},
        A.createElement("span",{className:"text-[11px] text-muted-foreground"},"Interleaved:"),
        A.createElement("select",{
          value:draft.interleaved,
          onChange:e=>setDraft(d=>({...d,interleaved:e.target.value})),
          className:"h-7 px-2 rounded !bg-muted !border !border-border text-[11px] text-foreground outline-none"
        },
          A.createElement("option",{value:"auto"},"Auto"),
          A.createElement("option",{value:"reasoning_content"},"reasoning_content (DeepSeek/Qwen/Kimi)"),
          A.createElement("option",{value:"reasoning_details"},"reasoning_details (OpenRouter)"),
          A.createElement("option",{value:"none"},"Standard")
        )
      )
    ),
    A.createElement("div",{className:"flex flex-wrap items-center justify-between gap-2 pt-0.5"},
      A.createElement("div",{className:"flex flex-wrap items-center gap-2.5 text-xs"},
        A.createElement("span",{className:"text-[11px] text-muted-foreground"},"Input Modalities:"),
        ["text","image","video","audio","pdf"].map(mod=>A.createElement("label",{key:mod,className:"flex items-center gap-1 cursor-pointer"},
          A.createElement("input",{type:"checkbox",disabled:mod==="text",checked:(draft.inputModalities||["text"]).includes(mod),onChange:()=>toggleMod(mod)}),
          mod.toUpperCase()
        ))
      ),
      A.createElement("button",{
        type:"button",
        onClick:()=>setDraft(d=>({...d,showCost:!d.showCost})),
        className:"text-[11px] text-link hover:underline bg-transparent border-none cursor-pointer"
      },draft.showCost?"Hide Pricing":"Optional Cost ($/1M)")
    ),
    draft.showCost&&A.createElement("div",{className:"grid grid-cols-2 sm:grid-cols-4 gap-2"},
      A.createElement("input",{type:"number",step:"any",placeholder:"Input $/1M",value:draft.costInput,onChange:e=>setDraft(d=>({...d,costInput:e.target.value})),className:inputCls+" font-mono"}),
      A.createElement("input",{type:"number",step:"any",placeholder:"Output $/1M",value:draft.costOutput,onChange:e=>setDraft(d=>({...d,costOutput:e.target.value})),className:inputCls+" font-mono"}),
      A.createElement("input",{type:"number",step:"any",placeholder:"Cache Read $",value:draft.costCacheRead,onChange:e=>setDraft(d=>({...d,costCacheRead:e.target.value})),className:inputCls+" font-mono"}),
      A.createElement("input",{type:"number",step:"any",placeholder:"Cache Write $",value:draft.costCacheWrite,onChange:e=>setDraft(d=>({...d,costCacheWrite:e.target.value})),className:inputCls+" font-mono"})
    ),
    A.createElement("div",{className:"flex items-center justify-end gap-2 pt-1 border-t border-border/60"},
      A.createElement(aB,{variant:"secondary",size:"xs",onClick:onCancel},"Cancel"),
      A.createElement(aB,{variant:"primary",size:"xs",disabled:!!busy||!draft.id.trim(),onClick:onSubmit},submitLabel)
    )
  );
}
function _AgyApiKeysScreen(){
  ${bindLocalSyms}
  var [viewPage,setViewPage]=(0,A.useState)("apikey"),
      initViewRef=(0,A.useRef)(!1),
      [tab,setTab]=(0,A.useState)("visual"),
      [authState,setAuthState]=(0,A.useState)({mode:"apikey",activeSlotId:"google-acc-1",slots:[]}),
      [newAccLabel,setNewAccLabel]=(0,A.useState)(""),
      [showNewOAuthInput,setShowNewOAuthInput]=(0,A.useState)(!1),
      [showAddForm,setShowAddForm]=(0,A.useState)(!1),
      [rawText,setRawText]=(0,A.useState)(""),
      [configPath,setConfigPath]=(0,A.useState)("~/.gemini/antigravity.json"),
      [providers,setProviders]=(0,A.useState)([]),
      [editKeys,setEditKeys]=(0,A.useState)({}),
      [revealed,setRevealed]=(0,A.useState)({}),
      [addAccountFor,setAddAccountFor]=(0,A.useState)(null),
      [accForm,setAccForm]=(0,A.useState)({name:"",apiKey:"",show:!1}),
      [addModelFor,setAddModelFor]=(0,A.useState)(null),
      [mForm,setMForm]=(0,A.useState)(_makeEmptyModelDraft),
      [pForm,setPForm]=(0,A.useState)({
        preset:"openrouter",id:"openrouter",name:"OpenRouter",npm:"@ai-sdk/openrouter",
        baseURL:"https://openrouter.ai/api/v1",accountName:"",apiKey:"",showKey:!1,
        showAdv:!1,setCacheKey:!1,timeout:"",customHeaders:""
      }),
      [showNewProvModelForm,setShowNewProvModelForm]=(0,A.useState)(!1),
      [pModelDraft,setPModelDraft]=(0,A.useState)(_makeEmptyModelDraft),
      [stagedModels,setStagedModels]=(0,A.useState)([]),
      [discovered,setDiscovered]=(0,A.useState)([]),
      [selectedDisc,setSelectedDisc]=(0,A.useState)({}),
      [plusCfg,setPlusCfg]=(0,A.useState)({proxyEnabled:!1,proxyUrl:"",autoRotateOAuth:!0,oauthQuotaThresholdPct:1,oauthCooldownMinutes:30,autoRotateApiKeys:!0,apiKeyCooldownMinutes:10}),
      [cooldowns,setCooldowns]=(0,A.useState)({apiItems:[],oauthItems:[]}),
      [telemetry,setTelemetry]=(0,A.useState)({totalRequests:0,totalPromptTokens:0,totalCompletionTokens:0,totalCostUsd:0,lastTokPerSec:0,avgTokPerSec:0,lastTtftMs:0}),
      [busy,setBusy]=(0,A.useState)(null),
      [banner,setBanner]=(0,A.useState)(null);

  var refreshModelsInHub=()=>{
    try{window.dispatchEvent(new Event("focus"))}catch{}
  };

  var applyServerSummary=j=>{
    if(j.rawText!==void 0)setRawText(j.rawText);
    if(j.configPath)setConfigPath(j.configPath);
    if(j.providers){
      setProviders(j.providers);
      var ek={};
      for(var p of j.providers)ek[p.id]=p.apiKey||"";
      setEditKeys(ek);
    }
  };

  var loadConfig=(0,A.useCallback)(async()=>{
    setBusy("load");
    try{
      var [r,ra,rp]=await Promise.all([
        fetch("${gwBase}/__agy_config/get"),
        fetch("${gwBase}/__agy_auth/status"),
        fetch("${gwBase}/__agy_plus/get").catch(()=>null)
      ]);
      var j=await r.json();
      var ja=await ra.json();
      var jp=rp?await rp.json().catch(()=>null):null;
      applyServerSummary(j);
      if(ja&&ja.mode){
        setAuthState(ja);
        if(!initViewRef.current){initViewRef.current=!0;setViewPage(ja.mode);}
      }
      if(jp){
        if(jp.settings)setPlusCfg(jp.settings);
        if(jp.cooldowns)setCooldowns(jp.cooldowns);
        if(jp.telemetry)setTelemetry(jp.telemetry);
      }
    }catch(e){
      setBanner({ok:!1,text:"Failed loading config: "+e.message});
    }finally{
      setBusy(null);
    }
  },[]);

  var handleSavePlusSettings=async()=>{
    setBusy("save-plus");setBanner(null);
    try{
      var r=await fetch("${gwBase}/__agy_plus/save",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(plusCfg)});
      var j=await r.json();
      if(j?.settings)setPlusCfg(j.settings);
      if(j?.cooldowns)setCooldowns(j.cooldowns);
      setBanner({ok:!0,text:j?.proxyReloaded?"Saved Proxy & Quota Rotation settings (Language Server updated).":"Saved Proxy & Quota Rotation settings."});
    }catch(e){
      setBanner({ok:!1,text:e.message});
    }finally{
      setBusy(null);
    }
  };

  var handleTestProxy=async()=>{
    setBusy("test-proxy");setBanner(null);
    try{
      var r=await fetch("${gwBase}/__agy_plus/test_proxy",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({proxyUrl:plusCfg.proxyUrl})});
      var j=await r.json();
      setBanner({ok:!!j.ok,text:j.message||"Proxy tested"});
    }catch(e){
      setBanner({ok:!1,text:e.message});
    }finally{
      setBusy(null);
    }
  };

  var handleClearCooldowns=async()=>{
    setBusy("clear-cd");
    try{
      var r=await fetch("${gwBase}/__agy_plus/clear_cooldowns",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"});
      var j=await r.json();
      if(j?.cooldowns)setCooldowns(j.cooldowns);
      setBanner({ok:!0,text:"Cleared all model quota cooldowns."});
    }catch{}finally{setBusy(null);}
  };

  var handleResetTelemetry=async()=>{
    setBusy("reset-tel");
    try{
      var r=await fetch("${gwBase}/__agy_plus/reset_telemetry",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"});
      var j=await r.json();
      if(j?.telemetry){setTelemetry(j.telemetry);Object.assign(_agyTelemetryState,j.telemetry);}
    }catch{}finally{setBusy(null);}
  };

  var syncLiveRendererAfterModeSwitch=async(nextMode)=>{
    window.__AGY_CURRENT_AUTH_MODE__=nextMode;
    try{
      if(window.__agyCore){
        await window.__agyCore.authService?.checkCurrentAuthStatus?.();
        await window.__agyCore.cloudCodeService?.loadCodeAssist?.(void 0,void 0,!0);
      }
      window.dispatchEvent(new Event("focus"));
    }catch{}
  };

  var triggerDirectBrowserGoogleLogin=async(clearInMemFirst)=>{
    window.__AGY_CURRENT_AUTH_MODE__="google_oauth";
    setBanner({ok:!0,text:"Chrome opened — choose or enter your Google Account email in the browser."});
    var lsClient=window.__agyCore?.authService?._lsClient;
    if(lsClient&&typeof lsClient.login==="function"){
      try{
        if(clearInMemFirst&&typeof lsClient.authLogout==="function"){
          try{await lsClient.authLogout({})}catch{}
        }
        var loginRes=await lsClient.login({isGcpTos:!1,enableBusinessLogin:!0});
        if(loginRes?.authResult?.hasValidAuth){
          // 1. Immediately finalize & update UI in ~25ms using fast native keyring reader + auto-focus window!
          var fin=await fetch("${gwBase}/__agy_auth/finalize_oauth_login",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"});
          var fj=await fin.json();
          if(fj&&Array.isArray(fj.slots))setAuthState({mode:fj.mode,activeSlotId:fj.activeSlotId,slots:fj.slots});
          setBusy(null);
          setBanner({ok:!0,text:fj?.email?("Signed in as "+fj.email):"Signed in with Google Account."});

          // 2. Refresh Cloud Code models & full display name asynchronously in background (non-blocking!)
          (async()=>{
            try{
              await syncLiveRendererAfterModeSwitch("google_oauth");
              var us=await lsClient.getUserStatus({});
              var uEmail=us?.userStatus?.email||"";
              var uName=us?.userStatus?.name||"";
              if(uEmail||uName){
                var r2=await fetch("${gwBase}/__agy_auth/record_email",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:uEmail,name:uName})});
                var j2=await r2.json();
                if(j2&&Array.isArray(j2.slots))setAuthState({mode:j2.mode,activeSlotId:j2.activeSlotId,slots:j2.slots});
              }
            }catch{}
          })();
        }else{
          var cr=await fetch("${gwBase}/__agy_auth/cancel_oauth_login",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"});
          var cj=await cr.json();
          if(cj&&cj.mode){setAuthState(cj);void syncLiveRendererAfterModeSwitch(cj.mode);}
          setBanner({ok:!1,text:"Google Sign-In was cancelled."});
        }
      }catch(err){
        var cr2=await fetch("${gwBase}/__agy_auth/cancel_oauth_login",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"}).catch(()=>null);
        var cj2=cr2?await cr2.json().catch(()=>null):null;
        if(cj2&&cj2.mode){setAuthState(cj2);void syncLiveRendererAfterModeSwitch(cj2.mode);}
        setBanner({ok:!1,text:"Sign-In failed: "+(err?.message||"cancelled")});
      }
    }else{
      await window.__agyCore?.authService?.loginWithRedirect?.({isGcpTos:!1,enableBusinessLogin:!0});
    }
  };

  var handleSwitchAuthMode=async(nextMode,slotId,forceSignIn)=>{
    setBusy("switch-auth");
    setBanner(null);
    try{
      var r=await fetch("${gwBase}/__agy_auth/switch_mode",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({mode:nextMode,slotId:slotId||void 0})});
      var j=await r.json();
      if(j&&j.mode)setAuthState(j);
      if(nextMode==="google_oauth"&&forceSignIn){
        await triggerDirectBrowserGoogleLogin(!1);
      }else{
        setBusy(null);
        setBanner({ok:!0,text:nextMode==="google_oauth"?"Switched to Google Account (OAuth).":"Switched to API Key & Providers."});
        void syncLiveRendererAfterModeSwitch(nextMode);
      }
    }catch(e){
      setBanner({ok:!1,text:e.message});
    }finally{
      setBusy(null);
    }
  };

  var handleAddOAuthAccount=async()=>{
    setBusy("add-oauth");
    setBanner(null);
    try{
      var r=await fetch("${gwBase}/__agy_auth/add_oauth_slot",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({label:""})});
      var j=await r.json();
      if(j&&j.mode)setAuthState(j);
      await triggerDirectBrowserGoogleLogin(!!j?.alreadyInOAuthMode);
    }catch(e){
      setBanner({ok:!1,text:e.message});
    }finally{
      setBusy(null);
    }
  };

  var handleDeleteOAuthSlot=async(slotId)=>{
    setBusy("del-oauth-"+slotId);
    setBanner(null);
    try{
      var r=await fetch("${gwBase}/__agy_auth/delete_oauth_slot",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({slotId})});
      var j=await r.json();
      if(j&&j.mode){
        setAuthState(j);
        if(j.switchedToApiKey){
          await syncLiveRendererAfterModeSwitch("apikey");
        }
      }
    }catch(e){
      setBanner({ok:!1,text:e.message});
    }finally{
      setBusy(null);
    }
  };

  (0,A.useEffect)(()=>{loadConfig()},[loadConfig]);

  var selectPreset=presetKey=>{
    var pr=_AGY_PROVIDER_PRESETS.find(x=>x.preset===presetKey);
    if(!pr)return;
    setPForm(prev=>({
      ...prev,
      preset:pr.preset,
      id:pr.id,
      name:pr.name,
      npm:pr.npm,
      baseURL:pr.baseURL
    }));
    setDiscovered([]);setSelectedDisc({});
  };

  var handleSaveJson=async()=>{
    setBusy("save");setBanner(null);
    try{
      var r=await fetch("${gwBase}/__agy_config/save",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({rawText})});
      var j=await r.json();
      if(!r.ok||!j.success)throw new Error(j.message||"Failed to save JSON");
      applyServerSummary(j);
      refreshModelsInHub();
      setBanner({ok:!0,text:"Saved antigravity.json and synced "+j.syncedModels+" model entries live."});
    }catch(e){
      setBanner({ok:!1,text:e.message});
    }finally{
      setBusy(null);
    }
  };

  var handleTestDraftConnection=async()=>{
    setBusy("test-draft");setBanner(null);
    try{
      var r=await fetch("${gwBase}/__agy_config/test_draft",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({npm:pForm.npm,baseURL:pForm.baseURL,apiKey:pForm.apiKey})});
      var j=await r.json();
      setBanner({ok:!!j.valid,text:j.message||"Connection tested"});
    }catch(e){
      setBanner({ok:!1,text:e.message});
    }finally{
      setBusy(null);
    }
  };

  var handleFetchRemoteModels=async()=>{
    setBusy("discover");setBanner(null);
    try{
      var r=await fetch("${gwBase}/__agy_config/discover_models",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({npm:pForm.npm,baseURL:pForm.baseURL,apiKey:pForm.apiKey})});
      var j=await r.json();
      if(!r.ok||!j.success)throw new Error(j.message||"Could not fetch models");
      setDiscovered(j.models||[]);
      var sel={};
      for(var m of (j.models||[]).slice(0,8))sel[m.id]=!0;
      setSelectedDisc(sel);
      setBanner({ok:!0,text:"Fetched "+(j.models||[]).length+" models."});
    }catch(e){
      setBanner({ok:!1,text:e.message});
    }finally{
      setBusy(null);
    }
  };

  var handleStageManualModel=()=>{
    if(!pModelDraft.id.trim())return;
    setStagedModels(prev=>[...prev.filter(x=>x.id!==pModelDraft.id.trim()),{...pModelDraft,id:pModelDraft.id.trim(),name:pModelDraft.name.trim()||pModelDraft.id.trim()}]);
    setPModelDraft(_makeEmptyModelDraft());
    setShowNewProvModelForm(!1);
  };

  var handleCreateProvider=async()=>{
    setBusy("create-prov");setBanner(null);
    try{
      var modelsToSave=[...stagedModels];
      for(var dm of discovered){
        if(selectedDisc[dm.id]&&!modelsToSave.some(x=>x.id===dm.id))modelsToSave.push(dm);
      }
      if(showNewProvModelForm&&pModelDraft.id.trim()&&!modelsToSave.some(x=>x.id===pModelDraft.id.trim())){
        modelsToSave.push({...pModelDraft,id:pModelDraft.id.trim(),name:pModelDraft.name.trim()||pModelDraft.id.trim()});
      }
      var r=await fetch("${gwBase}/__agy_config/add_provider",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({
          id:pForm.id.trim()||pForm.name.trim(),
          name:pForm.name.trim()||pForm.id.trim(),
          npm:pForm.npm,
          baseURL:pForm.baseURL.trim(),
          accountName:pForm.accountName.trim(),
          apiKey:pForm.apiKey.trim(),
          setCacheKey:pForm.setCacheKey,
          timeout:pForm.timeout,
          customHeaders:pForm.customHeaders,
          models:modelsToSave
        })
      });
      var j=await r.json();
      if(!r.ok||!j.success)throw new Error(j.message||"Could not add provider");
      applyServerSummary(j);
      refreshModelsInHub();
      setShowAddForm(!1);
      setShowNewProvModelForm(!1);
      setStagedModels([]);setDiscovered([]);setSelectedDisc({});
      setPModelDraft(_makeEmptyModelDraft());
      setBanner({ok:!0,text:"Provider saved and synced ("+j.syncedModels+" active model entries)."});
    }catch(e){
      setBanner({ok:!1,text:e.message});
    }finally{
      setBusy(null);
    }
  };

  var handleAddModelToProvider=async(pid)=>{
    if(!mForm.id.trim()){setBanner({ok:!1,text:"Enter a Model ID first."});return}
    setBusy("add-m-"+pid);setBanner(null);
    try{
      var r=await fetch("${gwBase}/__agy_config/add_model",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({
          providerId:pid,
          modelId:mForm.id.trim(),
          ...mForm,
          name:mForm.name.trim()||mForm.id.trim()
        })
      });
      var j=await r.json();
      if(!r.ok||!j.success)throw new Error(j.message||"Could not add model");
      applyServerSummary(j);
      refreshModelsInHub();
      setAddModelFor(null);
      setMForm(_makeEmptyModelDraft());
      setBanner({ok:!0,text:"Added model to "+pid+"."});
    }catch(e){
      setBanner({ok:!1,text:e.message});
    }finally{
      setBusy(null);
    }
  };

  var handleDeleteModel=async(pid,mid)=>{
    setBusy("del-m-"+pid+"-"+mid);setBanner(null);
    try{
      var r=await fetch("${gwBase}/__agy_config/delete_model",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({providerId:pid,modelId:mid})});
      var j=await r.json();
      if(!r.ok||!j.success)throw new Error(j.message||"Delete failed");
      applyServerSummary(j);
      refreshModelsInHub();
    }catch(e){
      setBanner({ok:!1,text:e.message});
    }finally{
      setBusy(null);
    }
  };

  var handleInsertTemplate=()=>{
    try{
      var parsed=JSON.parse(rawText||"{}");
      parsed.provider=parsed.provider||{};
      var newId="custom-"+(Object.keys(parsed.provider).length+1);
      parsed.provider[newId]={
        name:"Custom Provider",
        npm:"@ai-sdk/openai-compatible",
        options:{baseURL:"https://api.example.com/v1",apiKey:"YOUR_API_KEY",setCacheKey:!0},
        models:{
          "model-id":{
            name:"Custom Model",
            limit:{context:262144,output:65536},
            attachment:!0,reasoning:!0,tool_call:!0,temperature:!0,
            modalities:{input:["text","image"],output:["text"]}
          }
        }
      };
      setRawText(JSON.stringify(parsed,null,2));
      setBanner({ok:!0,text:'Inserted template provider "'+newId+'". Edit fields and click Save & Sync.'});
    }catch(e){
      setBanner({ok:!1,text:"Fix current JSON syntax first: "+e.message});
    }
  };

  var handleSaveProviderKey=async(pid)=>{
    setBusy("key-"+pid);setBanner(null);
    try{
      var r=await fetch("${gwBase}/__agy_config/update_key",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({providerId:pid,apiKey:editKeys[pid]||""})});
      var j=await r.json();
      if(!r.ok||!j.success)throw new Error(j.message||"Update failed");
      applyServerSummary(j);
      setBanner({ok:!0,text:'Updated API key for "'+pid+'".'});
    }catch(e){
      setBanner({ok:!1,text:e.message});
    }finally{
      setBusy(null);
    }
  };

  var handleTestProvider=async(pid,name)=>{
    setBusy("tst-"+pid);setBanner(null);
    try{
      var r=await fetch("${gwBase}/__agy_config/test_provider",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({providerId:pid})});
      var j=await r.json();
      setBanner({ok:!!j.valid,text:name+": "+(j.message||"Tested")});
    }catch(e){
      setBanner({ok:!1,text:e.message});
    }finally{
      setBusy(null);
    }
  };

  var handleDeleteProvider=async(pid)=>{
    setBusy("del-"+pid);setBanner(null);
    try{
      var r=await fetch("${gwBase}/__agy_config/delete_provider",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({providerId:pid})});
      var j=await r.json();
      if(!r.ok||!j.success)throw new Error(j.message||"Delete failed");
      applyServerSummary(j);
      refreshModelsInHub();
      setBanner({ok:!0,text:'Removed provider "'+pid+'".'});
    }catch(e){
      setBanner({ok:!1,text:e.message});
    }finally{
      setBusy(null);
    }
  };

  var handleAddAccount=async(pid)=>{
    if(!accForm.apiKey.trim()){setBanner({ok:!1,text:"Please enter an API Key for the account."});return}
    setBusy("add-acc-"+pid);setBanner(null);
    try{
      var r=await fetch("${gwBase}/__agy_config/add_account",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({providerId:pid,name:accForm.name.trim(),apiKey:accForm.apiKey.trim()})});
      var j=await r.json();
      if(!r.ok||!j.success)throw new Error(j.message||"Failed adding account");
      applyServerSummary(j);
      setAddAccountFor(null);
      setAccForm({name:"",apiKey:"",show:!1});
      setBanner({ok:!0,text:"Account added and set active."});
    }catch(e){
      setBanner({ok:!1,text:e.message});
    }finally{
      setBusy(null);
    }
  };

  var handleActivateAccount=async(pid,accId)=>{
    setBusy("act-acc-"+accId);setBanner(null);
    try{
      var r=await fetch("${gwBase}/__agy_config/activate_account",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({providerId:pid,accountId:accId})});
      var j=await r.json();
      if(!r.ok||!j.success)throw new Error(j.message||"Failed switching account");
      applyServerSummary(j);
      setBanner({ok:!0,text:"Switched active account."});
    }catch(e){
      setBanner({ok:!1,text:e.message});
    }finally{
      setBusy(null);
    }
  };

  var handleDeleteAccount=async(pid,accId)=>{
    setBusy("del-acc-"+accId);setBanner(null);
    try{
      var r=await fetch("${gwBase}/__agy_config/delete_account",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({providerId:pid,accountId:accId})});
      var j=await r.json();
      if(!r.ok||!j.success)throw new Error(j.message||"Failed deleting account");
      applyServerSummary(j);
      setBanner({ok:!0,text:"Account removed."});
    }catch(e){
      setBanner({ok:!1,text:e.message});
    }finally{
      setBusy(null);
    }
  };

  var handleTestAccount=async(pid,accId,accName)=>{
    setBusy("tst-acc-"+accId);setBanner(null);
    try{
      var r=await fetch("${gwBase}/__agy_config/test_account",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({providerId:pid,accountId:accId})});
      var j=await r.json();
      setBanner({ok:!!j.valid,text:accName+": "+(j.message||"Tested")});
    }catch(e){
      setBanner({ok:!1,text:e.message});
    }finally{
      setBusy(null);
    }
  };

  var inputCls="h-8 px-3 rounded-lg !bg-muted !border !border-border text-xs text-foreground outline-none focus:!ring-1 focus:!ring-primary";
  var protoBadgeLabel=proto=>proto==="google-genai"?"Google GenAI":proto==="anthropic-messages"?"Anthropic Messages":proto==="azure-openai"?"Azure OpenAI":"OpenAI-Compatible";

  return A.createElement(UP,{
    title:"API Key & Account"
  },
    banner&&A.createElement("div",{
      className:"flex items-center justify-between gap-2 px-3.5 py-2.5 rounded-xl border text-xs "+(banner.ok?"bg-green-500/10 border-green-500/30 text-foreground":"bg-red-500/10 border-red-500/30 text-red-500")
    },
      A.createElement("span",null,banner.text),
      A.createElement("button",{type:"button",onClick:()=>setBanner(null),className:"p-0.5 hover:bg-secondary rounded cursor-pointer border-none bg-transparent text-current"},
        A.createElement(lt,{name:"close",size:14})
      )
    ),

    A.createElement("div",{className:"grid grid-cols-1 sm:grid-cols-3 gap-2.5"},
      A.createElement("button",{
        type:"button",
        onClick:()=>{initViewRef.current=!0;setViewPage("apikey")},
        className:"p-3 rounded-xl border cursor-pointer transition-colors flex items-center justify-between gap-2 text-left outline-none "+(viewPage==="apikey"?"bg-primary/10 border-primary":"bg-muted/30 border-border hover:bg-muted/60")
      },
        A.createElement("span",{className:"text-sm font-medium text-foreground"},"API Key & Providers"),
        authState.mode==="apikey"&&A.createElement("span",{className:"text-[10px] font-semibold px-1.5 py-0.5 rounded-full bg-green-500/15 text-green-500"},"Active")
      ),

      A.createElement("button",{
        type:"button",
        onClick:()=>{initViewRef.current=!0;setViewPage("google_oauth")},
        className:"p-3 rounded-xl border cursor-pointer transition-colors flex items-center justify-between gap-2 text-left outline-none "+(viewPage==="google_oauth"?"bg-primary/10 border-primary":"bg-muted/30 border-border hover:bg-muted/60")
      },
        A.createElement("span",{className:"text-sm font-medium text-foreground"},"Google Account Login (OAuth)"),
        authState.mode==="google_oauth"&&A.createElement("span",{className:"text-[10px] font-semibold px-1.5 py-0.5 rounded-full bg-green-500/15 text-green-500"},"Active")
      ),

      A.createElement("button",{
        type:"button",
        onClick:()=>{initViewRef.current=!0;setViewPage("plus_network");fetch("${gwBase}/__agy_plus/get").then(r=>r.json()).then(jp=>{if(jp?.cooldowns)setCooldowns(jp.cooldowns);if(jp?.telemetry)setTelemetry(jp.telemetry)}).catch(()=>{})},
        className:"p-3 rounded-xl border cursor-pointer transition-colors flex items-center justify-between gap-2 text-left outline-none "+(viewPage==="plus_network"?"bg-primary/10 border-primary":"bg-muted/30 border-border hover:bg-muted/60")
      },
        A.createElement("span",{className:"text-sm font-medium text-foreground"},"Proxy & Quota Rotation"),
        plusCfg.proxyEnabled&&A.createElement("span",{className:"text-[10px] font-semibold px-1.5 py-0.5 rounded-full bg-blue-500/15 text-blue-400"},"Proxy ON")
      )
    ),

    viewPage==="plus_network"
      ? A.createElement(A.Fragment,null,
          A.createElement(YP,{
            title:"Built-in HTTP / HTTPS / SOCKS5 Proxy",
            headerRight:A.createElement("div",{className:"flex items-center gap-2"},
              A.createElement(aB,{variant:"secondary",size:"xs",disabled:!!busy||!plusCfg.proxyUrl.trim(),onClick:handleTestProxy},busy==="test-proxy"?"Testing...":"Test Proxy"),
              A.createElement(aB,{variant:"primary",size:"xs",disabled:!!busy,onClick:handleSavePlusSettings},busy==="save-plus"?"Saving...":"Save & Apply")
            )
          },
            A.createElement(WP,null,
              A.createElement("div",{className:"p-3.5 flex flex-col gap-3"},
                A.createElement("label",{className:"flex items-center gap-2 text-xs font-medium text-foreground cursor-pointer"},
                  A.createElement("input",{type:"checkbox",checked:!!plusCfg.proxyEnabled,onChange:e=>setPlusCfg(p=>({...p,proxyEnabled:e.target.checked}))}),
                  "Route AI Models, Google OAuth & Plugin Downloads through Proxy"
                ),
                A.createElement("input",{
                  type:"text",
                  placeholder:"http://127.0.0.1:10809  or  socks5://127.0.0.1:10808  or  socks5://user:pass@host:port",
                  value:plusCfg.proxyUrl,
                  onChange:e=>setPlusCfg(p=>({...p,proxyUrl:e.target.value})),
                  className:inputCls+" font-mono w-full"
                })
              )
            )
          ),

          A.createElement(YP,{
            title:"Per-Model Auto Account Rotation (Quota Exhaustion)",
            headerRight:A.createElement(aB,{variant:"primary",size:"xs",disabled:!!busy,onClick:handleSavePlusSettings},busy==="save-plus"?"Saving...":"Save Rotation Rules")
          },
            A.createElement(WP,null,
              A.createElement("div",{className:"p-3.5 flex flex-col gap-3.5"},
                A.createElement("div",{className:"flex flex-col gap-2 p-3 rounded-lg bg-muted/30 border border-border"},
                  A.createElement("label",{className:"flex items-center gap-2 text-xs font-medium text-foreground cursor-pointer"},
                    A.createElement("input",{type:"checkbox",checked:!!plusCfg.autoRotateOAuth,onChange:e=>setPlusCfg(p=>({...p,autoRotateOAuth:e.target.checked}))}),
                    "Google Account (OAuth): Auto-switch to next Google Account when active model quota runs out"
                  ),
                  A.createElement("div",{className:"grid grid-cols-1 sm:grid-cols-2 gap-2.5 pt-1"},
                    A.createElement("div",{className:"flex flex-col gap-1"},
                      A.createElement("span",{className:"text-[11px] text-muted-foreground"},"Switch when model remaining quota <= (%)"),
                      A.createElement("input",{type:"number",min:0,max:50,value:plusCfg.oauthQuotaThresholdPct,onChange:e=>setPlusCfg(p=>({...p,oauthQuotaThresholdPct:Number(e.target.value)})),className:inputCls+" font-mono"})
                    ),
                    A.createElement("div",{className:"flex flex-col gap-1"},
                      A.createElement("span",{className:"text-[11px] text-muted-foreground"},"Exhausted model cooldown (minutes)"),
                      A.createElement("input",{type:"number",min:1,max:1440,value:plusCfg.oauthCooldownMinutes,onChange:e=>setPlusCfg(p=>({...p,oauthCooldownMinutes:Number(e.target.value)})),className:inputCls+" font-mono"})
                    )
                  )
                ),

                A.createElement("div",{className:"flex flex-col gap-2 p-3 rounded-lg bg-muted/30 border border-border"},
                  A.createElement("label",{className:"flex items-center gap-2 text-xs font-medium text-foreground cursor-pointer"},
                    A.createElement("input",{type:"checkbox",checked:!!plusCfg.autoRotateApiKeys,onChange:e=>setPlusCfg(p=>({...p,autoRotateApiKeys:e.target.checked}))}),
                    "API Key & Providers: Auto-switch to next Account key when active model hits quota / 429"
                  ),
                  A.createElement("div",{className:"grid grid-cols-1 sm:grid-cols-2 gap-2.5 pt-1"},
                    A.createElement("div",{className:"flex flex-col gap-1"},
                      A.createElement("span",{className:"text-[11px] text-muted-foreground"},"Per-(Account, Model) cooldown after 429 (minutes)"),
                      A.createElement("input",{type:"number",min:1,max:1440,value:plusCfg.apiKeyCooldownMinutes,onChange:e=>setPlusCfg(p=>({...p,apiKeyCooldownMinutes:Number(e.target.value)})),className:inputCls+" font-mono"})
                    )
                  )
                ),

                ((cooldowns.apiItems&&cooldowns.apiItems.length>0)||(cooldowns.oauthItems&&cooldowns.oauthItems.length>0))&&A.createElement("div",{className:"flex flex-col gap-2 p-2.5 rounded-lg border border-amber-500/30 bg-amber-500/5"},
                  A.createElement("div",{className:"flex items-center justify-between"},
                    A.createElement("span",{className:"text-xs font-medium text-foreground"},"Models currently cooling down on specific accounts"),
                    A.createElement(aB,{variant:"secondary",size:"xs",onClick:handleClearCooldowns},"Reset Cooldowns")
                  ),
                  A.createElement("div",{className:"flex flex-wrap gap-1.5"},
                    (cooldowns.apiItems||[]).map((it,idx)=>A.createElement("span",{key:"a"+idx,className:"px-2 py-0.5 rounded bg-muted text-[11px] font-mono text-foreground"},it.providerId+" / "+it.keyMask+" -> "+it.modelId+" ("+it.remainingSec+"s)")),
                    (cooldowns.oauthItems||[]).map((it,idx)=>A.createElement("span",{key:"o"+idx,className:"px-2 py-0.5 rounded bg-muted text-[11px] font-mono text-foreground"},it.slotId+" -> "+it.modelLabel+" ("+it.remainingPct+"%)"))
                  )
                )
              )
            )
          ),

          A.createElement(YP,{
            title:"Live Speed, Latency & Session Cost Telemetry",
            headerRight:A.createElement(aB,{variant:"secondary",size:"xs",disabled:!!busy,onClick:handleResetTelemetry},"Reset Session Stats")
          },
            A.createElement(WP,null,
              A.createElement("div",{className:"p-3.5 grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs"},
                A.createElement("div",{className:"p-2.5 rounded-lg bg-muted/30 border border-border flex flex-col gap-0.5"},
                  A.createElement("span",{className:"text-[11px] text-muted-foreground"},"Last / Avg Speed"),
                  A.createElement("span",{className:"text-sm font-semibold font-mono text-foreground"},(telemetry.lastTokPerSec||0)+" / "+(telemetry.avgTokPerSec||0)+" tok/s")
                ),
                A.createElement("div",{className:"p-2.5 rounded-lg bg-muted/30 border border-border flex flex-col gap-0.5"},
                  A.createElement("span",{className:"text-[11px] text-muted-foreground"},"Last Latency (TTFT)"),
                  A.createElement("span",{className:"text-sm font-semibold font-mono text-foreground"},(telemetry.lastTtftMs||0)+" ms")
                ),
                A.createElement("div",{className:"p-2.5 rounded-lg bg-muted/30 border border-border flex flex-col gap-0.5"},
                  A.createElement("span",{className:"text-[11px] text-muted-foreground"},"Session Tokens"),
                  A.createElement("span",{className:"text-sm font-semibold font-mono text-foreground"},((telemetry.totalPromptTokens||0)+(telemetry.totalCompletionTokens||0)).toLocaleString())
                ),
                A.createElement("div",{className:"p-2.5 rounded-lg bg-muted/30 border border-border flex flex-col gap-0.5"},
                  A.createElement("span",{className:"text-[11px] text-muted-foreground"},"Est. Session Cost"),
                  A.createElement("span",{className:"text-sm font-semibold font-mono text-foreground"},"$"+Number(telemetry.totalCostUsd||0).toFixed(4))
                )
              )
            )
          )
        )
      : viewPage==="google_oauth"
      ? A.createElement(YP,{
          title:"Google Accounts ("+(authState.slots?authState.slots.length:0)+")",
          headerRight:A.createElement("div",{className:"flex items-center gap-2"},
            authState.mode!=="google_oauth"&&authState.slots&&authState.slots.length>0&&A.createElement(aB,{
              variant:"secondary",size:"xs",disabled:!!busy,
              onClick:()=>handleSwitchAuthMode("google_oauth",authState.activeSlotId,!authState.slots.find(x=>x.id===authState.activeSlotId)?.hasSavedCreds)
            },"Activate Google Account Mode"),
            A.createElement(aB,{
              variant:"primary",size:"xs",disabled:!!busy,
              onClick:handleAddOAuthAccount
            },busy==="add-oauth"?"Opening Chrome...":"+ Add Google Account")
          )
        },
          A.createElement(WP,null,
            A.createElement("div",{className:"p-3.5 flex flex-col gap-2.5"},
              (!authState.slots||authState.slots.length===0)
                ? A.createElement("div",{className:"py-6 text-center text-xs text-muted-foreground"},'No Google accounts connected. Click "+ Add Google Account" above to open Chrome and sign in.')
                : authState.slots.map(sl=>{
                    var isCurrent=authState.mode==="google_oauth"&&authState.activeSlotId===sl.id;
                    return A.createElement("div",{
                      key:sl.id,
                      className:"flex items-center justify-between gap-2 px-3 py-2 rounded-lg border "+(isCurrent?"bg-primary/5 border-primary/30":"bg-muted/20 border-border")
                    },
                      A.createElement("div",{className:"flex items-center gap-2 min-w-0"},
                        A.createElement("span",{className:"text-sm font-medium text-foreground truncate"},sl.name||sl.label),
                        sl.email&&A.createElement("span",{className:"text-xs text-muted-foreground truncate"},"("+sl.email+")"),
                        !sl.email&&!sl.hasSavedCreds&&A.createElement("span",{className:"text-[11px] text-muted-foreground"},"(Not signed in)"),
                        isCurrent&&A.createElement("span",{className:"text-[10px] font-semibold px-1.5 py-0.5 rounded-full bg-green-500/15 text-green-500"},"Active")
                      ),
                      A.createElement("div",{className:"flex items-center gap-1.5 shrink-0"},
                        (!isCurrent||!sl.hasSavedCreds)&&A.createElement(aB,{
                          variant:"primary",size:"xs",disabled:!!busy,
                          onClick:()=>handleSwitchAuthMode("google_oauth",sl.id,!sl.hasSavedCreds)
                        },sl.hasSavedCreds?"Switch Account":"Sign In"),
                        A.createElement(aB,{
                          variant:"secondary",size:"xs",disabled:!!busy,
                          onClick:()=>handleDeleteOAuthSlot(sl.id),
                          className:"text-red-500 hover:bg-red-500/10 border-red-500/20"
                        },busy==="del-oauth-"+sl.id?"...":"Remove")
                      )
                    );
                  })
            )
          )
        )
      : A.createElement(A.Fragment,null,
          authState.mode!=="apikey"&&A.createElement("div",{className:"flex items-center justify-between gap-2 px-3.5 py-2.5 rounded-xl border border-border bg-muted/30"},
            A.createElement("span",{className:"text-xs text-muted-foreground"},"Currently using Google Account Login (OAuth)."),
            A.createElement(aB,{variant:"primary",size:"xs",disabled:!!busy,onClick:()=>handleSwitchAuthMode("apikey")},"Activate API Key Mode")
          ),

          A.createElement("div",{className:"flex items-center justify-between gap-2 flex-wrap"},
      A.createElement("div",{className:"inline-flex p-0.5 rounded-lg bg-muted border border-border"},
        A.createElement("button",{
          type:"button",
          onClick:()=>setTab("visual"),
          className:"px-3 py-1 rounded-md text-xs font-medium border-none cursor-pointer transition-colors "+(tab==="visual"?"bg-background text-foreground shadow-sm":"bg-transparent text-muted-foreground hover:text-foreground")
        },"Accounts & Providers ("+providers.length+")"),
        A.createElement("button",{
          type:"button",
          onClick:()=>setTab("json"),
          className:"px-3 py-1 rounded-md text-xs font-medium border-none cursor-pointer transition-colors "+(tab==="json"?"bg-background text-foreground shadow-sm":"bg-transparent text-muted-foreground hover:text-foreground")
        },"JSON Config (antigravity.json)")
      ),
      A.createElement("div",{className:"flex items-center gap-2"},
        A.createElement(aB,{
          variant:showAddForm?"secondary":"primary",
          size:"xs",
          onClick:()=>{setTab("visual");setShowAddForm(v=>!v)}
        },showAddForm?"Cancel Add Provider":"+ Add Provider"),
        A.createElement(aB,{variant:"secondary",size:"xs",disabled:!!busy,onClick:loadConfig},"Reload")
      )
    ),

    showAddForm&&tab==="visual"&&A.createElement(YP,{
      title:"Add New Provider",
      headerRight:A.createElement(aB,{variant:"ghost",size:"xs",onClick:()=>{setShowAddForm(!1);setShowNewProvModelForm(!1)}},"Cancel")
    },
      A.createElement(WP,null,
        A.createElement("div",{className:"p-4 flex flex-col gap-3"},
          A.createElement("div",{className:"grid grid-cols-1 sm:grid-cols-2 gap-2.5"},
            A.createElement("div",{className:"flex flex-col gap-1"},
              A.createElement("span",{className:"text-[11px] text-muted-foreground"},"Provider Preset (25+ Built-in Templates)"),
              A.createElement("select",{
                value:pForm.preset,
                onChange:e=>selectPreset(e.target.value),
                className:inputCls
              },
                _AGY_PROVIDER_PRESETS.map(pr=>A.createElement("option",{key:pr.preset,value:pr.preset},
                  pr.name||(pr.preset==="custom-anth"?"Custom Anthropic-Compatible":"Custom OpenAI-Compatible")
                ))
              )
            ),
            A.createElement("div",{className:"flex flex-col gap-1"},
              A.createElement("span",{className:"text-[11px] text-muted-foreground"},"SDK / Wire Protocol"),
              A.createElement("select",{
                value:pForm.npm,
                onChange:e=>setPForm(p=>({...p,npm:e.target.value})),
                className:inputCls
              },
                _AGY_SDK_OPTIONS.map(opt=>A.createElement("option",{key:opt.value,value:opt.value},opt.label))
              )
            )
          ),

          A.createElement("div",{className:"grid grid-cols-1 sm:grid-cols-2 gap-2.5"},
            A.createElement("input",{
              type:"text",placeholder:"Provider ID (e.g. openrouter, anthropic, logfare)",
              value:pForm.id,onChange:e=>setPForm(p=>({...p,id:e.target.value})),
              className:inputCls+" font-mono"
            }),
            A.createElement("input",{
              type:"text",placeholder:"Display Name (e.g. OpenRouter)",
              value:pForm.name,onChange:e=>setPForm(p=>({...p,name:e.target.value})),
              className:inputCls
            })
          ),

          A.createElement("div",{className:"grid grid-cols-1 sm:grid-cols-3 gap-2.5"},
            A.createElement("input",{
              type:"text",
              placeholder:pForm.npm.includes("google")?"Base URL (optional for Google)":"Base URL (e.g. https://openrouter.ai/api/v1)",
              value:pForm.baseURL,onChange:e=>setPForm(p=>({...p,baseURL:e.target.value})),
              className:inputCls+" font-mono"
            }),
            A.createElement("input",{
              type:"text",
              placeholder:"Account Name / Email (e.g. Account 1)",
              value:pForm.accountName,onChange:e=>setPForm(p=>({...p,accountName:e.target.value})),
              className:inputCls
            }),
            A.createElement("div",{className:"flex items-center gap-1.5"},
              A.createElement("div",{className:"relative flex-1 flex items-center"},
                A.createElement("input",{
                  type:pForm.showKey?"text":"password",
                  placeholder:"API Key (sk-... / AIza...)",
                  value:pForm.apiKey,onChange:e=>setPForm(p=>({...p,apiKey:e.target.value})),
                  className:"w-full pr-8 font-mono "+inputCls
                }),
                A.createElement("button",{
                  type:"button",onClick:()=>setPForm(p=>({...p,showKey:!p.showKey})),
                  className:"absolute right-2 flex items-center text-muted-foreground hover:text-foreground bg-transparent border-none cursor-pointer p-0"
                },A.createElement(lt,{name:pForm.showKey?"visibility_off":"visibility",size:14}))
              ),
              A.createElement(aB,{variant:"secondary",size:"xs",disabled:!!busy||!pForm.apiKey.trim(),onClick:handleTestDraftConnection},busy==="test-draft"?"...":"Test")
            )
          ),

          A.createElement("div",{className:"flex items-center justify-between"},
            A.createElement("button",{
              type:"button",
              onClick:()=>setPForm(p=>({...p,showAdv:!p.showAdv})),
              className:"text-xs text-link hover:underline bg-transparent border-none cursor-pointer p-0"
            },pForm.showAdv?"Hide Advanced Provider Options":"Advanced Options (Custom Headers, Cache Key, Timeout)"),
            A.createElement("label",{className:"flex items-center gap-1.5 text-xs text-muted-foreground cursor-pointer"},
              A.createElement("input",{type:"checkbox",checked:pForm.setCacheKey,onChange:e=>setPForm(p=>({...p,setCacheKey:e.target.checked}))}),
              "Enable Prompt Cache Key (setCacheKey)"
            )
          ),

          pForm.showAdv&&A.createElement("div",{className:"grid grid-cols-1 sm:grid-cols-3 gap-2.5 p-2.5 rounded-lg bg-muted/40 border border-border"},
            A.createElement("input",{
              type:"number",placeholder:"Timeout ms (e.g. 120000)",
              value:pForm.timeout,onChange:e=>setPForm(p=>({...p,timeout:e.target.value})),
              className:inputCls+" font-mono"
            }),
            A.createElement("input",{
              type:"text",
              placeholder:'Custom Headers JSON (e.g. {"HTTP-Referer":"https://app.local"})',
              value:pForm.customHeaders,onChange:e=>setPForm(p=>({...p,customHeaders:e.target.value})),
              className:"sm:col-span-2 font-mono "+inputCls
            })
          ),

          A.createElement("div",{className:"border-t border-border pt-3 flex flex-col gap-2.5"},
            A.createElement("div",{className:"flex items-center justify-between flex-wrap gap-2"},
              A.createElement("span",{className:"text-xs font-medium text-foreground"},"Provider Models ("+stagedModels.length+" staged)"),
              A.createElement("div",{className:"flex items-center gap-2"},
                A.createElement(aB,{
                  variant:"secondary",size:"xs",
                  disabled:!!busy||(!pForm.apiKey.trim()&&!pForm.npm.includes("anthropic")&&!pForm.baseURL.includes("127.0.0.1")&&!pForm.baseURL.includes("localhost")),
                  onClick:handleFetchRemoteModels
                },busy==="discover"?"Fetching...":"Fetch Models from Endpoint"),
                A.createElement(aB,{
                  variant:showNewProvModelForm?"secondary":"primary",
                  size:"xs",
                  onClick:()=>{setShowNewProvModelForm(v=>!v);setPModelDraft(_makeEmptyModelDraft())}
                },showNewProvModelForm?"Cancel Model":"+ Add Custom Model")
              )
            ),

            stagedModels.length>0&&A.createElement("div",{className:"flex flex-wrap gap-1.5"},
              stagedModels.map(sm=>A.createElement("span",{
                key:sm.id,
                className:"inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-primary/10 border border-primary/30 text-[11px] text-foreground font-mono"
              },
                sm.name||sm.id,
                A.createElement("button",{
                  type:"button",
                  onClick:()=>setStagedModels(prev=>prev.filter(x=>x.id!==sm.id)),
                  className:"ml-0.5 text-muted-foreground hover:text-red-500 bg-transparent border-none cursor-pointer p-0 leading-none"
                },"×")
              ))
            ),

            discovered.length>0&&A.createElement("div",{className:"flex flex-col gap-1.5"},
              A.createElement("div",{className:"flex items-center justify-between text-[11px] text-muted-foreground"},
                A.createElement("span",null,"Select fetched models to include:"),
                A.createElement("button",{type:"button",onClick:()=>{setDiscovered([]);setSelectedDisc({})},className:"text-xs text-red-500 hover:underline bg-transparent border-none cursor-pointer"},"Clear / Cancel Fetched")
              ),
              A.createElement("div",{className:"max-h-40 overflow-y-auto p-2 rounded-lg bg-muted/60 border border-border grid grid-cols-1 sm:grid-cols-2 gap-1.5"},
                discovered.map(dm=>A.createElement("label",{key:dm.id,className:"flex items-center gap-2 text-xs text-foreground cursor-pointer truncate"},
                  A.createElement("input",{
                    type:"checkbox",
                    checked:!!selectedDisc[dm.id],
                    onChange:e=>setSelectedDisc(prev=>({...prev,[dm.id]:e.target.checked}))
                  }),
                  A.createElement("span",{className:"truncate font-mono"},dm.id)
                ))
              )
            ),

            showNewProvModelForm&&A.createElement(_AgyModelFormFields,{
              draft:pModelDraft,
              setDraft:setPModelDraft,
              submitLabel:"+ Stage Model",
              onSubmit:handleStageManualModel,
              onCancel:()=>{setShowNewProvModelForm(!1);setPModelDraft(_makeEmptyModelDraft())},
              busy:busy,
              inputCls:inputCls
            }),

            A.createElement("div",{className:"flex items-center justify-end gap-2 pt-2 border-t border-border"},
              A.createElement(aB,{variant:"secondary",size:"sm",onClick:()=>{setShowAddForm(!1);setShowNewProvModelForm(!1);setDiscovered([]);setStagedModels([])}},"Cancel"),
              A.createElement(aB,{variant:"primary",size:"sm",disabled:!!busy,onClick:handleCreateProvider},busy==="create-prov"?"Saving...":"Save Provider")
            )
          )
        )
      )
    ),

    tab==="json"
      ? A.createElement(YP,{
          title:"antigravity.json",
          headerRight:A.createElement("div",{className:"flex items-center gap-2"},
            A.createElement(aB,{variant:"secondary",size:"xs",disabled:!!busy,onClick:handleInsertTemplate},"+ Provider Template"),
            A.createElement(aB,{variant:"primary",size:"xs",disabled:!!busy,onClick:handleSaveJson},busy==="save"?"Saving & Syncing...":"Save & Sync Models")
          )
        },
          A.createElement(WP,null,
            A.createElement("div",{className:"p-3 flex flex-col gap-2.5"},
              A.createElement("div",{className:"flex items-center justify-between text-[11px] text-muted-foreground"},
                A.createElement("span",{className:"font-mono truncate"},configPath),
                A.createElement("button",{
                  type:"button",
                  onClick:()=>navigator.clipboard?.writeText(configPath),
                  className:"text-xs text-link hover:underline bg-transparent border-none cursor-pointer"
                },"Copy File Path")
              ),
              A.createElement("textarea",{
                value:rawText,
                onChange:e=>setRawText(e.target.value),
                spellCheck:!1,
                rows:22,
                className:"w-full p-3 rounded-lg !bg-muted !border !border-border font-mono text-xs leading-relaxed text-foreground outline-none focus:!ring-1 focus:!ring-primary resize-y"
              }),
              A.createElement("div",{className:"flex items-center justify-between gap-2"},
                A.createElement("span",{className:"text-[11px] text-muted-foreground"},"Supports OpenAI, Anthropic, Google GenAI, OpenRouter, DeepSeek, Groq, xAI, Ollama, Azure & custom endpoints."),
                A.createElement(aB,{variant:"primary",size:"sm",disabled:!!busy,onClick:handleSaveJson},busy==="save"?"Saving...":"Save & Sync Models")
              )
            )
          )
        )
      : A.createElement(YP,{title:"Configured Providers ("+providers.length+")"},
          A.createElement(WP,null,
            providers.length===0
              ? A.createElement("div",{className:"py-8 px-4 text-center text-xs text-muted-foreground"},'No providers configured. Click "+ Add Provider" above or use "JSON Config".')
              : providers.map(p=>{
                  var isAddingModel=addModelFor===p.id;
                  var isAddingAccount=addAccountFor===p.id;
                  var accList=Array.isArray(p.accounts)?p.accounts:[];
                  return A.createElement("div",{key:p.id,className:"p-3.5 flex flex-col gap-2.5"},
                    A.createElement("div",{className:"flex items-center justify-between gap-2 flex-wrap"},
                      A.createElement("div",{className:"flex items-center gap-2 min-w-0"},
                        A.createElement("span",{className:"text-sm font-medium text-foreground"},p.name),
                        A.createElement("span",{className:"text-[10px] px-1.5 py-0.5 rounded-full bg-secondary text-secondary-foreground border border-border"},protoBadgeLabel(p.protocol)),
                        A.createElement("span",{className:"text-xs text-muted-foreground"},accList.length+" "+(accList.length===1?"account":"accounts")+" · "+p.modelCount+" models")
                      ),
                      A.createElement("div",{className:"flex items-center gap-1.5 shrink-0"},
                        A.createElement(aB,{
                          variant:isAddingAccount?"secondary":"primary",
                          size:"xs",
                          disabled:!!busy,
                          onClick:()=>{
                            if(isAddingAccount){setAddAccountFor(null);setAccForm({name:"",apiKey:"",show:!1})}
                            else{setAddAccountFor(p.id);setAccForm({name:"",apiKey:"",show:!1})}
                          }
                        },isAddingAccount?"Cancel":"+ Add Account"),
                        A.createElement(aB,{
                          variant:"secondary",
                          size:"xs",
                          disabled:!!busy,
                          onClick:()=>{
                            if(isAddingModel){setAddModelFor(null);setMForm(_makeEmptyModelDraft())}
                            else{setAddModelFor(p.id);setMForm(_makeEmptyModelDraft())}
                          }
                        },isAddingModel?"Cancel":"+ Add Model"),
                        A.createElement(aB,{variant:"secondary",size:"xs",disabled:!!busy,onClick:()=>handleTestProvider(p.id,p.name)},busy==="tst-"+p.id?"Testing...":"Test"),
                        A.createElement(aB,{variant:"secondary",size:"xs",disabled:!!busy,onClick:()=>handleDeleteProvider(p.id),className:"text-red-500 hover:bg-red-500/10 border-red-500/20"},busy==="del-"+p.id?"Deleting...":"Delete Provider")
                      )
                    ),
                    p.baseURL&&A.createElement("div",{className:"text-[11px] font-mono text-muted-foreground truncate"},p.baseURL),

                    A.createElement("div",{className:"flex flex-col gap-1.5"},
                      accList.length===0
                        ? A.createElement("div",{className:"text-xs text-muted-foreground py-1"},'No accounts added yet. Click "+ Add Account" to add an API key.')
                        : accList.map(acc=>{
                            var revKey=!!revealed[acc.id];
                            return A.createElement("div",{
                              key:acc.id,
                              className:"flex items-center justify-between gap-2 px-2.5 py-1.5 rounded-lg border "+(acc.active?"bg-primary/5 border-primary/30":"bg-muted/30 border-border")
                            },
                              A.createElement("div",{className:"flex items-center gap-2 min-w-0"},
                                A.createElement("span",{className:"text-xs font-medium text-foreground truncate"},acc.name),
                                acc.active&&A.createElement("span",{className:"text-[10px] font-semibold px-1.5 py-0.5 rounded-full bg-green-500/15 text-green-500 select-none"},"Active"),
                                A.createElement("span",{className:"text-xs font-mono text-muted-foreground truncate"},revKey?acc.apiKey:acc.maskedKey)
                              ),
                              A.createElement("div",{className:"flex items-center gap-1 shrink-0"},
                                A.createElement(aB,{
                                  variant:"ghost",size:"xs",
                                  onClick:()=>setRevealed(prev=>({...prev,[acc.id]:!prev[acc.id]})),
                                  title:revKey?"Hide":"Show"
                                },A.createElement(lt,{name:revKey?"visibility_off":"visibility",size:14})),
                                !acc.active&&A.createElement(aB,{
                                  variant:"secondary",size:"xs",
                                  disabled:!!busy,
                                  onClick:()=>handleActivateAccount(p.id,acc.id)
                                },busy==="act-acc-"+acc.id?"...":"Switch"),
                                A.createElement(aB,{
                                  variant:"secondary",size:"xs",
                                  disabled:!!busy,
                                  onClick:()=>handleTestAccount(p.id,acc.id,acc.name)
                                },busy==="tst-acc-"+acc.id?"...":"Test"),
                                A.createElement(aB,{
                                  variant:"secondary",size:"xs",
                                  disabled:!!busy,
                                  onClick:()=>handleDeleteAccount(p.id,acc.id),
                                  className:"text-red-500 hover:bg-red-500/10 border-red-500/20"
                                },busy==="del-acc-"+acc.id?"...":"Remove")
                              )
                            );
                          })
                    ),

                    isAddingAccount&&A.createElement("div",{className:"p-3 rounded-xl bg-muted/40 border border-border flex flex-col gap-2.5"},
                      A.createElement("div",{className:"grid grid-cols-1 sm:grid-cols-3 gap-2"},
                        A.createElement("input",{
                          type:"text",
                          placeholder:"Account Name / Email (e.g. Account 2, Work)",
                          value:accForm.name,
                          onChange:e=>setAccForm(a=>({...a,name:e.target.value})),
                          className:inputCls
                        }),
                        A.createElement("div",{className:"sm:col-span-2 relative flex items-center"},
                          A.createElement("input",{
                            type:accForm.show?"text":"password",
                            placeholder:"Paste Account API Key",
                            value:accForm.apiKey,
                            onChange:e=>setAccForm(a=>({...a,apiKey:e.target.value})),
                            onKeyDown:e=>{e.key==="Enter"&&handleAddAccount(p.id)},
                            className:"w-full pr-8 font-mono "+inputCls
                          }),
                          A.createElement("button",{
                            type:"button",
                            onClick:()=>setAccForm(a=>({...a,show:!a.show})),
                            className:"absolute right-2 flex items-center text-muted-foreground hover:text-foreground bg-transparent border-none cursor-pointer p-0"
                          },A.createElement(lt,{name:accForm.show?"visibility_off":"visibility",size:14}))
                        )
                      ),
                      A.createElement("div",{className:"flex items-center justify-between gap-2"},
                        A.createElement("span",{className:"text-[11px] text-muted-foreground"},"Multiple accounts automatically rotate if the active account hits a quota/rate limit (429)."),
                        A.createElement("div",{className:"flex items-center gap-2"},
                          A.createElement(aB,{variant:"secondary",size:"xs",onClick:()=>{setAddAccountFor(null);setAccForm({name:"",apiKey:"",show:!1})}},"Cancel"),
                          A.createElement(aB,{variant:"primary",size:"xs",disabled:!!busy||!accForm.apiKey.trim(),onClick:()=>handleAddAccount(p.id)},busy==="add-acc-"+p.id?"Saving...":"Save Account")
                        )
                      )
                    ),

                    (p.modelItems&&p.modelItems.length>0)&&A.createElement("div",{className:"flex flex-wrap gap-1.5 pt-1"},
                      p.modelItems.map(mi=>A.createElement("span",{
                        key:mi.id,
                        className:"inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-muted border border-border text-[11px] text-foreground font-mono"
                      },
                        mi.name||mi.id,
                        A.createElement("button",{
                          type:"button",
                          title:"Remove model",
                          onClick:()=>handleDeleteModel(p.id,mi.id),
                          className:"ml-0.5 text-muted-foreground hover:text-red-500 bg-transparent border-none cursor-pointer p-0 leading-none"
                        },"×")
                      ))
                    ),

                    isAddingModel&&A.createElement(_AgyModelFormFields,{
                      draft:mForm,
                      setDraft:setMForm,
                      submitLabel:busy==="add-m-"+p.id?"Adding...":"Add Model",
                      onSubmit:()=>handleAddModelToProvider(p.id),
                      onCancel:()=>{setAddModelFor(null);setMForm(_makeEmptyModelDraft())},
                      busy:busy,
                      inputCls:inputCls
                    })
                  );
                })
          )
        )
      )
  );
};
function _AgyLiveTelemetryRing({modelConfig:_mc}){
  ${bindLocalSyms}
  if(_mc?.label||_mc?.modelId)_agyActiveModelHint=String(_mc.label||_mc.modelId);
  var [tel,setTel]=(0,A.useState)(()=>({..._agyTelemetryState}));
  var [open,setOpen]=(0,A.useState)(!1);
  var btnRef=(0,A.useRef)(null);
  (0,A.useEffect)(()=>{
    var onTel=s=>setTel(s);
    _agyTelListeners.add(onTel);
    fetch("${gwBase}/__agy_quota").then(r=>r.json()).then(j=>{
      if(j&&j.modelContextLimits)Object.assign(_agyModelCtxMap,j.modelContextLimits);
      if(j&&j.telemetry)_agyEmitTel(j.telemetry);
    }).catch(()=>{});
    return()=>{_agyTelListeners.delete(onTel)};
  },[]);
  (0,A.useEffect)(()=>{
    if(!open)return;
    var onDoc=ev=>{if(btnRef.current&&btnRef.current.contains(ev.target))return;setOpen(!1)};
    document.addEventListener("mousedown",onDoc,true);
    return()=>document.removeEventListener("mousedown",onDoc,true);
  },[open]);
  var fmtTok=n=>{n=Number(n)||0;return n>=1e6?(n/1e6).toFixed(1)+"M":n>=1e3?(n/1e3).toFixed(1)+"K":String(n)};
  var mId=String(_mc?.modelId||"").toLowerCase(),mLbl=String(_mc?.label||"").toLowerCase();
  var maxCtx=_agyModelCtxMap[mId]||_agyModelCtxMap[mLbl]||1048576;
  var totalSess=(tel?.totalPromptTokens||0)+(tel?.totalCompletionTokens||0);
  var pct=maxCtx>0?Math.min(100,Math.round((totalSess/maxCtx)*100)):0;
  return A.createElement("div",{ref:btnRef,className:"relative inline-flex items-center"},
    A.createElement("button",{
      type:"button",
      "data-testid":"agy-live-telemetry-ring",
      onClick:()=>{setOpen(o=>!o);fetch("${gwBase}/__agy_quota").then(r=>r.json()).then(j=>{if(j&&j.telemetry)_agyEmitTel(j.telemetry)}).catch(()=>{})},
      className:"inline-flex items-center gap-1.5 h-7 px-2 rounded-lg text-xs text-muted-foreground hover:text-foreground hover:bg-secondary/60 bg-transparent border-none cursor-pointer transition-colors"
    },
      A.createElement("span",{className:"inline-block w-2 h-2 rounded-full "+(tel?.isStreaming?"bg-emerald-400 animate-pulse":"bg-primary/70")}),
      A.createElement("span",{className:"font-mono text-[11px]"},pct+"%"),
      (tel&&(tel.lastTokPerSec>0||tel.isStreaming))&&A.createElement("span",{className:"font-mono text-[11px] "+(tel.isStreaming?"text-emerald-400":"text-muted-foreground")},Number(tel.lastTokPerSec||0).toFixed(1)+" tok/s")
    ),
    open&&A.createElement("div",{
      className:"absolute bottom-9 right-0 w-60 rounded-xl border border-border bg-background shadow-2xl p-3 flex flex-col gap-2 z-50 text-xs"
    },
      A.createElement("div",{className:"flex items-center justify-between border-b border-border pb-1.5"},
        A.createElement("span",{className:"font-semibold text-foreground"},"Live Telemetry & Context"),
        A.createElement("span",{className:"font-mono text-[11px] text-muted-foreground"},fmtTok(maxCtx)+" max")
      ),
      A.createElement("div",{className:"grid grid-cols-2 gap-x-3 gap-y-1.5 text-[11px]"},
        A.createElement("div",{className:"flex justify-between"},A.createElement("span",{className:"text-muted-foreground"},"Speed"),A.createElement("span",{className:"font-mono font-medium text-foreground"},Number(tel?.lastTokPerSec||0).toFixed(1)+" tok/s")),
        A.createElement("div",{className:"flex justify-between"},A.createElement("span",{className:"text-muted-foreground"},"TTFT"),A.createElement("span",{className:"font-mono font-medium text-foreground"},(tel?.lastTtftMs||0)+" ms")),
        A.createElement("div",{className:"flex justify-between"},A.createElement("span",{className:"text-muted-foreground"},"Session"),A.createElement("span",{className:"font-mono font-medium text-foreground"},fmtTok(totalSess))),
        A.createElement("div",{className:"flex justify-between"},A.createElement("span",{className:"text-muted-foreground"},"Cost"),A.createElement("span",{className:"font-mono font-medium text-foreground"},"$"+Number(tel?.totalCostUsd||0).toFixed(4)))
      )
    )
  );
}`;
}

function execNearAnchor(txt, anchor, re, before = 200, after = 400) {
    const idx = txt.indexOf(anchor);
    if (idx === -1) return null;
    const winStart = Math.max(0, idx - before);
    const winEnd = Math.min(txt.length, idx + anchor.length + after);
    return re.exec(txt.slice(winStart, winEnd));
}

function replaceNearAnchor(txt, anchor, re, replacer, before = 250, after = 700, all = false) {
    let pos = 0;
    let out = txt;
    while (true) {
        const idx = out.indexOf(anchor, pos);
        if (idx === -1) break;
        const winStart = Math.max(0, idx - before);
        const winEnd = Math.min(out.length, idx + anchor.length + after);
        const slice = out.slice(winStart, winEnd);
        const replaced = slice.replace(re, replacer);
        if (replaced !== slice) {
            out = out.slice(0, winStart) + replaced + out.slice(winEnd);
            pos = winStart + replaced.length;
        } else {
            pos = idx + anchor.length;
        }
        if (!all) break;
    }
    return out;
}

function detectUiBundleSymbols(txt) {
    const mR = execNearAnchor(txt, '"aria-label":"Customizations views"', /([A-Za-z0-9_$]+)\.createElement\("nav",\{"aria-label":"Customizations views"/, 60, 40)
        || execNearAnchor(txt, 'title:"Appearance",description:"Configure the agent', /([A-Za-z0-9_$]+)\.createElement\([A-Za-z0-9_$]+,\{title:"Appearance",description:"Configure the agent/, 60, 40);
    const mP = execNearAnchor(txt, ".createPortal(", /([A-Za-z0-9_$]+)\.createPortal\(/, 30, 10);
    const mUP = execNearAnchor(txt, 'title:"Appearance",description:"Configure the agent', /\.createElement\(([A-Za-z0-9_$]+),\{title:"Appearance",description:"Configure the agent/, 40, 40);
    const mYP = execNearAnchor(txt, 'title:"Account",description:"Manage your plan', /title:"Account",description:"Manage your plan[\s\S]{0,200}\.createElement\(([A-Za-z0-9_$]+),\{title:"General"\}/, 20, 260);
    const mWP = execNearAnchor(txt, 'className:"agy-card bg-transparent rounded-xl border border-border overflow-hidden divide-y divide-border"', /var ([A-Za-z0-9_$]+)=\(\{children:[a-z]\}\)=>[A-Za-z0-9_$]+\.createElement\("div",\{className:"agy-card bg-transparent rounded-xl border border-border overflow-hidden divide-y divide-border"\}/, 80, 40);
    const mXP = execNearAnchor(txt, 'rightElement:c,extraContent:d', /var ([A-Za-z0-9_$]+)=\(\{label:[a-z],description:[a-z],rightElement:[a-z],extraContent:[a-z]/, 60, 40);
    const mBtnIcon = execNearAnchor(txt, '"aria-label":"Dismiss Tip"', /\.createElement\(([A-Za-z0-9_$]+),\{variant:"ghost",size:"icon"[^}]*\},[A-Za-z0-9_$]+\.createElement\(([A-Za-z0-9_$]+),\{name:"close"/, 120, 120);
    const mSetMendel = execNearAnchor(txt, "setMendelFlagOverrides(", /setMendelFlagOverrides\(([A-Za-z0-9_$]+)\(([A-Za-z0-9_$]+),\{overrides:/, 20, 80);
    return {
        reactSym: (mR && mR[1]) || "A",
        portalSym: (mP && mP[1]) || "uy",
        pageHeaderSym: (mUP && mUP[1]) || "UP",
        sectionCardSym: (mYP && mYP[1]) || "YP",
        cardContainerSym: (mWP && mWP[1]) || "WP",
        cardRowSym: (mXP && mXP[1]) || "XP",
        btnSym: (mBtnIcon && mBtnIcon[1]) || "aB",
        iconSym: (mBtnIcon && mBtnIcon[2]) || "lt",
        pbFn: (mSetMendel && mSetMendel[1]) || "$b",
        setMendelSchema: (mSetMendel && mSetMendel[2]) || "Yga"
    };
}

function patchUiMainBundleSource(rawTxt, gwBase) {
    const syms = detectUiBundleSymbols(rawTxt);
    const R = syms.reactSym;
    const BTN = syms.btnSym;
    const ICON = syms.iconSym;
    const defaultFlagsJson = JSON.stringify(DEFAULT_UNLOCKED_FLAGS);
    const providersScreenComponent = buildProvidersJsonScreenCode(gwBase, syms);
    const i18nEngineCode = buildAppearanceLanguageAndI18nCode(gwBase, syms);
    let txt = rawTxt;

    // 0a. Remove 'Check for Updates' from top-left Antigravity dropdown menu
    txt = replaceNearAnchor(
        txt,
        'label:"Check for Updates"',
        /([A-Za-z0-9_$]+)\?\.checkForUpdates&&([A-Za-z0-9_$]+)\.push\(\{label:"Check for Updates",onClick:\(\)=>\{\1\.checkForUpdates\?\.\(\)\}\}\);/,
        "",
        60,
        80
    );

    // 0. Enable DevMode + Unlock All Hidden Mendel Flags & UserCohort-Gated Features
    txt = replaceNearAnchor(
        txt,
        "window.__APP_CONFIG__?.devMode",
        /function ([A-Za-z0-9_$]+)\(\)\{return typeof window==="undefined"\?!1:!!window\.__APP_CONFIG__\?\.devMode\}/,
        "function $1(){return!0}",
        80,
        20
    );
    txt = replaceNearAnchor(
        txt,
        "a.getMendelFlags(",
        /async function ([A-Za-z0-9_$]+)\(a\)\{var b=e,c=e;try\{try\{let d=c\(await b\(a\.getMendelFlags\(([A-Za-z0-9_$]+)\(([A-Za-z0-9_$]+),\{\}\)\)\)\)\.experimentConfig\?\.experiments\?\?\[\];a=\{\};for\(let f of d\)f\.keyString&&\(a\[f\.keyString\]=f\);return a\}/,
        (_m, fnName, pbFn, getSchema) =>
            `async function ${fnName}(a){var _lsRef=a,b=e,c=e;try{try{let d=c(await b(a.getMendelFlags(${pbFn}(${getSchema},{})))).experimentConfig?.experiments??[];a={};for(let _fl of ${defaultFlagsJson})a[_fl]={keyString:_fl,disabled:!1};for(let f of d)f.keyString&&(a[f.keyString]=f);try{let _ov={};for(let _fl of ${defaultFlagsJson})_ov[_fl]=!0;let _raw=typeof window!=="undefined"?window.localStorage.getItem("jetski.developer.customFlagOverrides"):null;if(_raw){let _parsed=JSON.parse(_raw);if(_parsed&&typeof _parsed==="object")Object.assign(_ov,_parsed)}${process.platform === "win32" ? '_ov["enable-programmatic-tools"]=!1;' : ""}_lsRef.setMendelFlagOverrides(${syms.pbFn}(${syms.setMendelSchema},{overrides:_ov})).catch(()=>{})}catch{}return a}`,
        100,
        260
    );
    txt = txt
        .replaceAll('userCohort:["google"],customFlag:"labs-inline-actions"', 'customFlag:"labs-inline-actions"')
        .replaceAll('userCohort:["google"],customFlag:"labs-autonomous-mode"', 'customFlag:"labs-autonomous-mode"')
        .replaceAll('userCohort:["google"],\ncustomFlag:"enable-conversation-sharing-prototype"', 'customFlag:"enable-conversation-sharing-prototype"')
        .replaceAll('userCohort:["google"],customFlag:"enable-conversation-sharing-prototype"', 'customFlag:"enable-conversation-sharing-prototype"')
        .replaceAll('customFlag:"context-window-selector",userCohort:["google"]', 'customFlag:"context-window-selector"')
        .replaceAll('customFlag:"enable-file-viewer-keyboard-navigation",userCohort:["google"]', 'customFlag:"enable-file-viewer-keyboard-navigation"')
        .replaceAll('customFlag:"enable-plugin-themes",userCohort:["google"]', 'customFlag:"enable-plugin-themes"')
        .replace(
            'labs:{feature:!1,applyFirst:[{runtimeGating:{userCohort:["google"]},feature:!0}]}',
            'labs:{feature:!0}'
        )
        .replace(
            'enableCompactionNotification:{feature:a.enableCompactionNotification??!1}',
            'enableCompactionNotification:{feature:!0}'
        )
        .replace(
            'enableRawErrorDetails:{feature:!1}',
            'enableRawErrorDetails:{feature:!0}'
        );
    txt = replaceNearAnchor(
        txt,
        'applyFirst:[{runtimeGating:{userCohort:["google"]},feature:{visible:!0}}]',
        /([A-Za-z0-9_$]+)=\{feature:\{visible:!1\},applyFirst:\[\{runtimeGating:\{userCohort:\["google"\]\},feature:\{visible:!0\}\}\],important:\[([A-Za-z0-9_$]+)\]\}/,
        "$1={feature:{visible:!0},important:[$2]}",
        50,
        50
    );
    txt = replaceNearAnchor(
        txt,
        'openArtifactInNewWindow:{feature:!1',
        /openArtifactInNewWindow:\{feature:!1,applyFirst:\[\{runtimeGating:\{host:\[[A-Za-z0-9_$.]+\],userCohort:\["google"\]\},feature:!0\}\]\}/,
        'openArtifactInNewWindow:{feature:!0}',
        10,
        140
    );
    txt = replaceNearAnchor(
        txt,
        'enableDefaultCustomizationsSetting:{feature:a.enableDefaultCustomizationsSetting',
        /enableDefaultCustomizationsSetting:\{feature:a\.enableDefaultCustomizationsSetting\?\?\s*!1\},enableBuildWithGooglePlugins:\{feature:a\.enableBuildWithGooglePlugins\?\?\s*!1\}/,
        'enableDefaultCustomizationsSetting:{feature:!0},enableBuildWithGooglePlugins:{feature:!0}',
        10,
        160
    );

    // 0b. Inject Native 'API Key & Account' Screen into Settings Sidebar (works for both v2.29 semicolon & v2.32 space-split)
    txt = txt.replace(
        '{screen:"Models"},{screen:"Customizations"}',
        '{screen:"Models"},{screen:"API Key & Account"},{screen:"Customizations"}'
    );
    txt = replaceNearAnchor(
        txt,
        'Models;Customizations',
        /([A-Za-z0-9_$]+)="General;Appearance;[^"]*Models;Customizations[^"]*"/,
        (m) => m.replace("Models;Customizations", "Models;API Key & Account;Customizations"),
        100,
        100
    );
    txt = replaceNearAnchor(
        txt,
        'Models Customizations',
        /([A-Za-z0-9_$]+)="General Appearance [^"]*Models Customizations[^"]*"\.split\(" "\)/,
        (_m, varName) => `${varName}=[...${_m.slice(varName.length + 1)},"API Key & Account"]`,
        100,
        100
    );
    txt = replaceNearAnchor(
        txt,
        'a.settings.isScreenVisible(',
        /\.filter\(([a-z])=>a\.settings\.isScreenVisible\(\1\)\)/,
        '.filter($1=>$1==="API Key & Account"||a.settings.isScreenVisible($1))',
        20,
        20
    );
    txt = txt.replace(
        'h&&(m=m.filter(p=>p==="Regroup Google3 Chats"||p==="Shortcuts"||p==="Running"||g.has(p)))',
        'h&&(m=m.filter(p=>p==="API Key & Account"||p==="Developer"||p==="Notifications"||p==="Regroup Google3 Chats"||p==="Shortcuts"||p==="Running"||g.has(p)))'
    );
    txt = replaceNearAnchor(
        txt,
        '==="Browser"||',
        /([a-z])&&\(([a-z])=\2\.filter\(([a-z])=>([A-Za-z0-9_$]+)\.includes\(\3\)\|\|\3==="Browser"\|\|\3==="Shortcuts"\|\|\3==="Running"\|\|([a-z])\.has\(\3\)\)\)/,
        '$1&&($2=$2.filter($3=>$3==="API Key & Account"||$3==="Developer"||$3==="Notifications"||$4.includes($3)||$3==="Browser"||$3==="Shortcuts"||$3==="Running"||$5.has($3)))',
        60,
        80
    );
    txt = replaceNearAnchor(
        txt,
        'switch(a){case "Account":',
        /(function [A-Za-z0-9_$]+\(a\)\{(?:if\([A-Za-z0-9_$]+\.includes\(a\)\)return [A-Za-z0-9_$]+\.createElement\([A-Za-z0-9_$]+,\{screen:a\}\);)?switch\(a\)\{(?=case "Account":))/,
        (match) => `${providersScreenComponent}\n${i18nEngineCode}\n${match}case "API Key & Account":return ${R}.createElement(_AgyApiKeysScreen,null);`,
        120,
        30
    );
    txt = replaceNearAnchor(
        txt,
        'title:"Appearance",description:"Configure the agent\'s visual theme and display preferences."',
        /(\.createElement\([A-Za-z0-9_$]+,\{title:"Appearance",description:"Configure the agent's visual theme and display preferences\."\},)/,
        `$1${R}.createElement(_AgyAppearanceLanguageCard,null),`,
        40,
        20
    );
    txt = replaceNearAnchor(
        txt,
        '==="Models"?"block":"none"',
        /([A-Za-z0-9_$]+\.createElement\("div",\{style:\{display:([a-z])==="Models"\?"block":"none"\}\},[A-Za-z0-9_$]+\.createElement\([A-Za-z0-9_$]+,\{isActive:\2==="Models"\}\)\),)/,
        `$1${R}.createElement("div",{style:{display:$2==="API Key & Account"?"block":"none"}},${R}.createElement(_AgyApiKeysScreen,null)),`,
        60,
        120
    );

    // 1. Account Branding + Dynamic Quota Sync (populates _agyModelCtxMap too!)
    txt = replaceNearAnchor(
        txt,
        "?.name?.trim()",
        /([a-z])=([a-z])\?\.name\?\.trim\(\),([a-z])=\2\?\.email\?\.trim\(\)/,
        `$1=$2?.name?.trim()||"Google Gemini",$3=(($2?.email&&$2.email!=="gemini@google.com"&&fetch("${gwBase}/__agy_auth/record_email",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:$2.email,name:$2.name||""})}).catch(()=>{})),$2?.email?.trim()||"gemini@google.com")`,
        15,
        40
    );
    txt = replaceNearAnchor(
        txt,
        '?"Enterprise Gateway":',
        /var ([A-Za-z])=d\?"Enterprise Gateway":c&&c\.userTier\?\.description/,
        'var $1=d?"Max":c&&c.userTier?.description||"Max"',
        20,
        60
    );
    txt = txt
        .replace('description:d?"Authenticated via Enterprise Gateway":', 'description:d?"Google Gemini Max Plan":')
        .replace('description:"Managed by Enterprise Gateway"', 'description:"gemini@google.com"');
    txt = replaceNearAnchor(
        txt,
        "?.context.isGcpTos??!1",
        /([a-z])=([a-z])\?\.context\.isGcpTos\?\?!1;\2=\2\?\.state\?\?"signedOut";var ([a-z])=([a-z])&&\4\.userTier\?\.description,([a-z])=\4\?\.userTier\?\.upgradeSubscriptionText\|\|"";/,
        '$1=!1;$2=$2?.state??"signedOut";var $3=$4&&$4.userTier?.description||"Max",$5=$4?.userTier?.upgradeSubscriptionText||"Google Gemini Max Plan & Custom JSON Providers";',
        10,
        160
    );
    txt = replaceNearAnchor(
        txt,
        ".CREDITS_FETCH_FAILED,",
        /d\.loadCodeAssist\([^)]*\)\.catch\(([A-Za-z0-9_$]+)=>\{b\([A-Za-z0-9_$.]+\.CREDITS_FETCH_FAILED,\1\)\}\)/,
        'd.loadCodeAssist?.(void 0,void 0,true)?.catch(()=>{})',
        60,
        30
    );
    txt = replaceNearAnchor(
        txt,
        ".core.cloudCodeService",
        /function ([A-Za-z0-9_$]+)\(\)\{var a=([A-Za-z0-9_$]+)\(\)\.core\.cloudCodeService,b=([A-Za-z0-9_$]+)\(\)\.get\("models"\)\?\.geminiModelsOnly===!0;return\(0,([A-Za-z0-9_$]+)\.useMemo\)\(\(\)=>\{if\(!b\|\|!a\.retrieveUserQuotaSummary\)return a;/,
        (_m, fnName, rdSym, hkSym, reactUseMemo) =>
            `function ${fnName}(){var _rc=${rdSym}().core;if(typeof window!=="undefined")window.__agyCore=_rc;var a=_rc.cloudCodeService,b=${hkSym}().get("models")?.geminiModelsOnly===!0;return(0,${reactUseMemo}.useMemo)(()=>{if(typeof window!=="undefined"&&window.__AGY_CURRENT_AUTH_MODE__!=="google_oauth")return{...a,retrieveUserQuotaSummary:async()=>fetch("${gwBase}/__agy_quota").then(r=>r.json()).then(j=>{if(j&&j.modelContextLimits)Object.assign(_agyModelCtxMap,j.modelContextLimits);if(j&&j.telemetry)Object.assign(_agyTelemetryState,j.telemetry);return j})};if(a&&a.retrieveUserQuotaSummary){var _origQ=a.retrieveUserQuotaSummary.bind(a);return{...a,retrieveUserQuotaSummary:async(..._qa)=>{let _qr=await _origQ(..._qa);try{if(_qr?.response?.groups)fetch("${gwBase}/__agy_auth/report_oauth_quota",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({groups:_qr.response.groups})}).catch(()=>{})}catch{}return _qr}};}if(!b||!a.retrieveUserQuotaSummary)return a;`,
        50,
        220
    );

    // 1b. Google OAuth Per-Model Auto Account Rotation + Live OAuth Speed Start (v2.29 & v2.32+)
    txt = replaceNearAnchor(
        txt,
        "y.sendUserCascadeMessage(x,{signal:v})",
        /l=async ([a-z])=>\{var \{signal:v,\.\.\.w\}=\1;\1=w\.senderWindowId\?\?([A-Za-z0-9_$]+)\(\);var x=([A-Za-z0-9_$]+)\(([A-Za-z0-9_$]+),\{\.\.\.w,\.\.\.\(\1\?\{senderWindowId:\1\}:\{\}\)\}\);([A-Za-z0-9_$]+\(x\.cascadeId,x\);)?return f\(y=>v\?y\.sendUserCascadeMessage\(x,\{signal:v\}\):y\.sendUserCascadeMessage\(x\)\)\}/,
        (_m, arg, winFn, pbFn, msgSchema, r0aCall) =>
            `l=async ${arg}=>{var {signal:v,...w}=${arg};${arg}=w.senderWindowId??${winFn}();var x=${pbFn}(${msgSchema},{...w,...(${arg}?{senderWindowId:${arg}}:{})});${r0aCall || ""}if(typeof window!=="undefined"&&window.__AGY_CURRENT_AUTH_MODE__==="google_oauth"){_agyOAuthStream={startMs:Date.now(),firstMs:0,chars:0,lastTickMs:0};_agyEmitTel({isStreaming:!0});try{let _pr=await fetch("${gwBase}/__agy_auth/auto_rotate_for_model",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({model:_agyActiveModelHint||"",exhaustedError:!1})}).then(r=>r.json());if(_pr?.rotated){try{await window.__agyCore?.authService?.checkCurrentAuthStatus?.();await window.__agyCore?.cloudCodeService?.loadCodeAssist?.(void 0,void 0,!0)}catch{}if(window.__agyShowToast)window.__agyShowToast("Model quota reached — switched to "+(_pr.newAccountLabel||"next Google Account"))}}catch{}}try{return await f(y=>v?y.sendUserCascadeMessage(x,{signal:v}):y.sendUserCascadeMessage(x))}catch(_err){if(typeof window!=="undefined"&&window.__AGY_CURRENT_AUTH_MODE__==="google_oauth"&&/RESOURCE_EXHAUSTED|quota|429|rate.?limit|exhausted/i.test(String(_err?.message||_err||""))){try{let _rr=await fetch("${gwBase}/__agy_auth/auto_rotate_for_model",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({model:_agyActiveModelHint||"",exhaustedError:!0})}).then(r=>r.json());if(_rr?.rotated){try{await window.__agyCore?.authService?.checkCurrentAuthStatus?.();await window.__agyCore?.cloudCodeService?.loadCodeAssist?.(void 0,void 0,!0)}catch{}if(window.__agyShowToast)window.__agyShowToast("Quota reached — auto-switched to "+(_rr.newAccountLabel||"next Google Account"));return await f(y=>v?y.sendUserCascadeMessage(x,{signal:v}):y.sendUserCascadeMessage(x))}}catch{}}throw _err;}}`,
        220,
        80,
        true
    );

    // 1c. Live Per-Second Streaming Speed Hook for Google OAuth Mode (streamAgentStateUpdates)
    txt = replaceNearAnchor(
        txt,
        "of m(d.call(a,f,g))){n();try{p&&(p=!1,l.resolve())",
        /try\{let p=!0;for await\(let ([a-z]) of m\(d\.call\(a,f,g\)\)\)\{n\(\);try\{p&&\(p=!1,l\.resolve\(\)\),n\(yield m\(\1\)\)\}finally\{m\(\)\}\}n\(\);l\.resolve\(\)\}/,
        'try{let p=!0;for await(let $1 of m(d.call(a,f,g))){n();try{if(typeof window!=="undefined"&&window.__AGY_CURRENT_AUTH_MODE__==="google_oauth"&&_agyOAuthStream.startMs>0){let _now=Date.now(),_sz=0;try{_sz=JSON.stringify($1).length}catch{}if(_sz>40){if(!_agyOAuthStream.firstMs)_agyOAuthStream.firstMs=_now;_agyOAuthStream.chars+=Math.round(_sz*0.35);if(_now-_agyOAuthStream.lastTickMs>=120){_agyOAuthStream.lastTickMs=_now;let _tok=Math.max(1,Math.round(_agyOAuthStream.chars/4)),_el=Math.max(80,_now-_agyOAuthStream.firstMs);_agyEmitTel({isStreaming:!0,lastTtftMs:Math.max(1,_agyOAuthStream.firstMs-_agyOAuthStream.startMs),lastTokPerSec:Number(((_tok/_el)*1000).toFixed(1))})}}}p&&(p=!1,l.resolve()),n(yield m($1))}finally{m()}}n();if(typeof window!=="undefined"&&window.__AGY_CURRENT_AUTH_MODE__==="google_oauth"&&_agyOAuthStream.startMs>0){_agyOAuthStream.startMs=0;_agyEmitTel({isStreaming:!1})}l.resolve()}',
        40,
        80
    );

    // 2. Context Window Ring + Live Telemetry (v2.29 native bqc + v2.32 fallback _AgyLiveTelemetryRing)
    txt = txt
        .replaceAll('contextUsageIndicator:{feature:!1', 'contextUsageIndicator:{feature:!0')
        .replaceAll('contextUsageIndicatorEnabled:{feature:{visible:!1}', 'contextUsageIndicatorEnabled:{feature:{visible:!0}')
        .replace(
            'function $pc(a){a=QB(a);return Rl(a,{selector:Vpc,equalityFn:Wpc})}',
            'function $pc(a){var _s=RB(a)||{getState:()=>void 0,onDidChange:()=>({dispose:()=>{}})};return Rl(_s,{selector:Vpc,equalityFn:Wpc})}'
        )
        .replaceAll(
            'contextUsageIndicator:g_&&d?A.createElement(bqc,{conversationId:d}):void 0',
            'contextUsageIndicator:g_?A.createElement(bqc,{conversationId:d,modelConfig:ia}):void 0'
        )
        .replace(
            'function bqc({conversationId:a}){a=$pc(a);var b=hk().get("inputComponent")?.showModelUsage===!0,[c,d]=(0,A.useState)(!1),f=Zpc(),g=(0,A.useCallback)(k=>{k&&f();d(k)},[f]);if(!a)return null;var h=Math.round(a.usedFraction*100);',
            'function bqc({conversationId:a,modelConfig:_mc}){a=$pc(a);if(_mc?.label||_mc?.modelId)_agyActiveModelHint=String(_mc.label||_mc.modelId);var [_tel,setTel]=(0,A.useState)(()=>({..._agyTelemetryState}));(0,A.useEffect)(()=>{var _onTel=s=>setTel(s);_agyTelListeners.add(_onTel);fetch("' + gwBase + '/__agy_quota").then(r=>r.json()).then(j=>{if(j&&j.modelContextLimits)Object.assign(_agyModelCtxMap,j.modelContextLimits);if(j&&j.telemetry)_agyEmitTel(j.telemetry)}).catch(()=>{});return()=>{_agyTelListeners.delete(_onTel)}},[]);var _mId=String(_mc?.modelId||"").toLowerCase(),_mLbl=String(_mc?.label||"").toLowerCase(),_mMax=_agyModelCtxMap[_mId]||_agyModelCtxMap[_mLbl]||(/gemma-4/i.test(_mId||_mLbl)?262144:(a?.maxTokens&&a.maxTokens!==256000?a.maxTokens:1048576));if(!a){a={usedTokens:0,maxTokens:_mMax,usedFraction:0,instructionTokens:0,conversationTokens:0,freeTokens:_mMax,compactedSinceLastCall:!1}}else if(a.maxTokens!==_mMax){var _uf=Math.min(1,a.usedTokens/_mMax);a={...a,maxTokens:_mMax,usedFraction:_uf,freeTokens:Math.max(0,_mMax-a.usedTokens)}}var b=!0,[c,d]=(0,A.useState)(!1),f=Zpc(),g=(0,A.useCallback)(k=>{if(k){f();fetch("' + gwBase + '/__agy_quota").then(r=>r.json()).then(j=>{if(j&&j.telemetry)_agyEmitTel(j.telemetry)}).catch(()=>{})}d(k)},[f]);var h=a.usedTokens>0?Math.max(1,Math.round(a.usedFraction*100)):0;'
        )
        .replace(
            'A.createElement(cqc,{fraction:a.usedFraction}),A.createElement("span",null,a.compactedSinceLastCall?"~":"",h,"%")))',
            'A.createElement(cqc,{fraction:a.usedFraction}),A.createElement("span",null,a.compactedSinceLastCall?"~":"",h,"%"),(_tel&&(_tel.lastTokPerSec>0||_tel.isStreaming))&&A.createElement("span",{className:"inline-flex items-center gap-1 ml-1 font-mono text-[11px] "+(_tel.isStreaming?"text-emerald-400":"text-muted-foreground")},_tel.isStreaming&&A.createElement("span",{className:"inline-block w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"}),(_tel.lastTokPerSec>0?Number(_tel.lastTokPerSec).toFixed(1):"0.0")," tok/s")))'
        )
        .replace(
            'A.createElement(dqc,{summary:a,percent:h}),b&&',
            'A.createElement(dqc,{summary:a,percent:h}),A.createElement("div",{className:"border-t border-border px-3 py-2 grid grid-cols-2 gap-x-3 gap-y-1 text-[11px] bg-muted/20"},A.createElement("div",{className:"flex justify-between"},A.createElement("span",{className:"text-muted-foreground"},"Speed"),A.createElement("span",{className:"font-mono font-medium text-foreground"},(_tel?.lastTokPerSec||0)+" tok/s")),A.createElement("div",{className:"flex justify-between"},A.createElement("span",{className:"text-muted-foreground"},"TTFT"),A.createElement("span",{className:"font-mono font-medium text-foreground"},(_tel?.lastTtftMs||0)+" ms")),A.createElement("div",{className:"flex justify-between"},A.createElement("span",{className:"text-muted-foreground"},"Session"),A.createElement("span",{className:"font-mono font-medium text-foreground"},Xpc((_tel?.totalPromptTokens||0)+(_tel?.totalCompletionTokens||0)))),A.createElement("div",{className:"flex justify-between"},A.createElement("span",{className:"text-muted-foreground"},"Cost"),A.createElement("span",{className:"font-mono font-medium text-foreground"},"$"+Number(_tel?.totalCostUsd||0).toFixed(4)))),b&&'
        );
    txt = replaceNearAnchor(
        txt,
        'case "contextUsageIndicatorEnabled":',
        /case "contextUsageIndicatorEnabled":return c\?\.get\("contextUsageIndicatorEnabled"\)===\s*"true"/,
        'case "contextUsageIndicatorEnabled":return c?.get("contextUsageIndicatorEnabled")!=="false"',
        10,
        100,
        true
    );
    txt = replaceNearAnchor(
        txt,
        '("contextUsageIndicatorEnabled",',
        /([A-Za-z0-9_$]+)\("contextUsageIndicatorEnabled",([A-Za-z0-9_$]+)\)===!0/,
        '$1("contextUsageIndicatorEnabled",!0)!==!1',
        20,
        40,
        true
    );
    txt = replaceNearAnchor(
        txt,
        "contextUsageIndicator:",
        /contextUsageIndicator:([A-Za-z0-9_$]+)&&([A-Za-z0-9_$]+)&&d\?([A-Za-z0-9_$]+)\.createElement\(\1,\{conversationId:d\}\):void 0/,
        `contextUsageIndicator:$1&&$2&&d?$3.createElement($1,{conversationId:d}):$3.createElement(_AgyLiveTelemetryRing,{conversationId:d,modelConfig:ua})`,
        10,
        120,
        true
    );

    // 3. Always show expandable Thinking / Thought Process blocks by default
    txt = txt.replaceAll(
        'case "verboseConversationSteps":return a.rootProvider.getState().userConfig?.userSettings?.verboseConversationSteps??!1',
        'case "verboseConversationSteps":return a.rootProvider.getState().userConfig?.userSettings?.verboseConversationSteps??!0'
    );
    txt = replaceNearAnchor(txt, ".verboseAgentChat??!1", /([A-Za-z0-9_$]+)\(\)\.verboseAgentChat\?\?!1/, "$1().verboseAgentChat??!0", 20, 10, true);
    txt = replaceNearAnchor(txt, "verboseAgentChat:", /verboseAgentChat:([a-z])\}=[A-Za-z0-9_$]+\(\),([a-z])=\1\?\?!1/, (m) => m.replace("??!1", "??!0"), 10, 40, true);

    // 4. Full Rich 3D Marketplace + Classic Plugins + One-Click Install/Uninstall
    txt = txt.replaceAll('b.getCascadeNuxes({})', 'Promise.resolve({nuxes:[]})');
    txt = replaceNearAnchor(txt, "v.getAvailableCascadePlugins(", /v\.getAvailableCascadePlugins\([A-Za-z0-9_$]+\([A-Za-z0-9_$]+,[a-z]\)\)/, 'Promise.resolve({plugins:[]})', 10, 60, true);
    txt = replaceNearAnchor(
        txt,
        "searchMarketplace:async",
        /searchMarketplace:async ([a-z])=>\s*f\(v=>v\.searchMarketplace\([A-Za-z0-9_$]+\([A-Za-z0-9_$]+,\{query:\1\.query\?\?"",groupId:\1\.groupId\?\?"",pageToken:\1\.pageToken\?\?""\}\)\)\)/,
        `searchMarketplace:async $1=>fetch("${gwBase}/__agy_plugins/marketplace_search",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({query:$1.query??"",groupId:$1.groupId??"",pageToken:$1.pageToken??""})}).then(r=>r.json())`,
        10,
        200,
        true
    );
    txt = replaceNearAnchor(
        txt,
        "getMarketplaceFeatured:async",
        /getMarketplaceFeatured:async\(\)=>f\(([a-z])=>\1\.getMarketplaceFeatured\([A-Za-z0-9_$]+\([A-Za-z0-9_$]+,\{\}\)\)\)/,
        `getMarketplaceFeatured:async()=>fetch("${gwBase}/__agy_plugins/marketplace_featured").then(r=>r.json())`,
        10,
        120,
        true
    );
    txt = replaceNearAnchor(
        txt,
        "getMarketplaceCustomization:async",
        /getMarketplaceCustomization:async ([a-z])=>f\(v=>v\.getMarketplaceCustomization\([A-Za-z0-9_$]+\([A-Za-z0-9_$]+,\{id:\1\.id,includePreview:\1\.includePreview\?\?!1\}\)\)\)/,
        `getMarketplaceCustomization:async $1=>fetch("${gwBase}/__agy_plugins/marketplace_item",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:$1.id})}).then(async r=>{const j=await r.json();if(!r.ok)throw new Error(j.error||"Not found");return j})`,
        10,
        180,
        true
    );
    txt = replaceNearAnchor(
        txt,
        "installCustomization:async",
        /installCustomization:async ([a-z])=>f\(v=>v\.installCustomization\([A-Za-z0-9_$]+\([A-Za-z0-9_$]+,\{id:\1\.id,bundleId:\1\.bundleId\}\)\)\)/,
        `installCustomization:async $1=>fetch("${gwBase}/__agy_plugins/install",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:$1.id})}).then(async r=>{const j=await r.json();if(!r.ok||!j.success)throw new Error(j.message||"Install failed");return j})`,
        10,
        160,
        true
    );
    txt = replaceNearAnchor(
        txt,
        "(c.installedFrom,a))}",
        /function ([A-Za-z0-9_$]+)\(a,b\)\{return b\.find\(c=>([A-Za-z0-9_$]+)\(c\.installedFrom,a\)\)\}/,
        'function $1(a,b){return b.find(c=>$2(c.installedFrom,a)||(c.path&&a?.id&&String(c.path).replace(/\\\\/g,"/").split("/").pop()===a.id))}',
        60,
        20
    );
    txt = replaceNearAnchor(
        txt,
        "getBuildWithGooglePlugins:async",
        /getBuildWithGooglePlugins:async\(\)=>f\(([a-z])=>\1\.getBuildWithGooglePlugins\([A-Za-z0-9_$]+\([A-Za-z0-9_$]+,\{\}\)\)\)/,
        `getBuildWithGooglePlugins:async()=>fetch("${gwBase}/__agy_plugins/list").then(r=>r.json())`,
        10,
        120,
        true
    );
    txt = replaceNearAnchor(
        txt,
        "downloadBuildWithGooglePlugin:async",
        /downloadBuildWithGooglePlugin:async ([a-z])=>f\(async v=>\{var w=[A-Za-z0-9_$]+\([A-Za-z0-9_$]+\);w\.pluginId=\1\.uid;return v\.downloadBuildWithGooglePlugin\(w\)\}\)/,
        `downloadBuildWithGooglePlugin:async $1=>fetch("${gwBase}/__agy_plugins/install",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({uid:$1.uid})}).then(async r=>{const j=await r.json();if(!r.ok||!j.success)throw new Error(j.message||"Plugin install failed");return j})`,
        10,
        180,
        true
    );
    txt = replaceNearAnchor(
        txt,
        "deletePlugin:async",
        /deletePlugin:async ([a-z])=>f\(async v=>\{var w=([A-Za-z0-9_$]+\([A-Za-z0-9_$]+\));w\.pluginId=\1\.pluginId;return v\.deletePlugin\(w\)\}\)/,
        `deletePlugin:async $1=>{await f(async v=>{var w=$2;w.pluginId=$1.pluginId;return v.deletePlugin(w)}).catch(()=>({}));await fetch("${gwBase}/__agy_plugins/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({pluginId:$1.pluginId})}).catch(()=>null);return {}}`,
        10,
        160,
        true
    );
    txt = txt
        .replace('h(C.plugins);let F=new Set;', 'h(C.plugins);let F=new Set(C.installedUids||[]);')
        .replace(
            '(G.path.endsWith(J)||G.path.endsWith(J+"/"))&&F.add(I)',
            '(String(G.path||"").replace(/\\\\/g,"/").endsWith(J)||String(G.path||"").replace(/\\\\/g,"/").endsWith(J+"/"))&&F.add(I)'
        );

    // 4b. Inject Sleek 'Install from GitHub' Pill Button + Centered Backdrop Modal inside Customizations Header (v2.29 Fyc & v2.32 AWc)
    txt = replaceNearAnchor(
        txt,
        '"aria-label":"Customizations views"',
        /function ([A-Za-z0-9_$]+)\(\{tab:a,onSelect:b\}\)\{return ([A-Za-z0-9_$]+)\.createElement\("nav",\{"aria-label":"Customizations views",className:"agy-pill inline-flex items-center h-8 rounded-lg border border-border bg-secondary\/20 p-0\.5 gap-0\.5 select-none","data-testid":"plugins-tabs"\},([A-Za-z0-9_$]+)\.map\(\(\{tab:c,to:d,label:f\}\)=>\{var g=c===a;return \2\.createElement\(([A-Za-z0-9_$]+),\{key:c,to:d,activeOptions:\{exact:!0\},"aria-current":g\?"page":void 0,onClick:\(\)=>\{g\|\|b\(c\)\},className:([A-Za-z0-9_$]+)\("([^"]+)",\s*g\?"bg-secondary text-foreground":"text-secondary-foreground hover:text-foreground"\),"data-testid":`plugins-tab-\$\{c\}`\},f\)\}\)\)\}/,
        (_m, fnName, rSym, tabsArr, linkSym, cnSym, baseCls) =>
            `function ${fnName}({tab:a,onSelect:b}){var [ghOpen,setGhOpen]=(0,${rSym}.useState)(!1),[ghUrl,setGhUrl]=(0,${rSym}.useState)(""),[ghBusy,setGhBusy]=(0,${rSym}.useState)(!1),[ghMsg,setGhMsg]=(0,${rSym}.useState)(null),inputRef=(0,${rSym}.useRef)(null);(0,${rSym}.useEffect)(()=>{if(!ghOpen)return;setTimeout(()=>{inputRef.current?.focus()},30);var onKey=ev=>{if(ev.key==="Escape"&&!ghBusy){setGhOpen(!1);setGhMsg(null)}};window.addEventListener("keydown",onKey);return()=>window.removeEventListener("keydown",onKey)},[ghOpen,ghBusy]);var doGhInstall=async()=>{if(!ghUrl.trim()||ghBusy)return;setGhBusy(!0);setGhMsg(null);try{var r=await fetch("${gwBase}/__agy_plugins/install_github",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url:ghUrl.trim()})}),j=await r.json();if(!r.ok||!j.success)throw new Error(j.message||"Install failed");setGhMsg({ok:!0,text:j.message||"Installed successfully!"});setGhUrl("");window.dispatchEvent(new Event("focus"));setTimeout(()=>{setGhOpen(!1);setGhMsg(null);b("installed");window.location.hash="#/customizations/installed"},800)}catch(err){setGhMsg({ok:!1,text:err.message})}finally{setGhBusy(!1)}};var ghIcon=${rSym}.createElement("svg",{viewBox:"0 0 16 16",width:14,height:14,fill:"currentColor","aria-hidden":"true",className:"shrink-0"},${rSym}.createElement("path",{d:"M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z"}));return ${rSym}.createElement(${rSym}.Fragment,null,${rSym}.createElement("div",{className:"inline-flex items-center gap-2"},${rSym}.createElement("button",{type:"button","data-testid":"install-from-github-btn",onClick:()=>{setGhOpen(!0);setGhMsg(null)},className:"agy-pill inline-flex items-center justify-center gap-1.5 h-8 px-3 rounded-lg border border-border bg-secondary/30 hover:bg-secondary text-xs font-medium text-foreground shrink-0 whitespace-nowrap transition-colors cursor-pointer select-none outline-none focus-visible:ring-1 focus-visible:ring-primary"},ghIcon,${rSym}.createElement("span",null,"Install from GitHub")),${rSym}.createElement("nav",{"aria-label":"Customizations views",className:"agy-pill inline-flex items-center h-8 rounded-lg border border-border bg-secondary/20 p-0.5 gap-0.5 select-none","data-testid":"plugins-tabs"},${tabsArr}.map(({tab:c,to:d,label:f})=>{var g=c===a;return ${rSym}.createElement(${linkSym},{key:c,to:d,activeOptions:{exact:!0},"aria-current":g?"page":void 0,onClick:()=>{g||b(c)},className:${cnSym}("${baseCls}",g?"bg-secondary text-foreground":"text-secondary-foreground hover:text-foreground"),"data-testid":"plugins-tab-"+c},f)}))),ghOpen&&${rSym}.createElement("div",{"data-testid":"github-install-modal",onMouseDown:ev=>{if(ev.target===ev.currentTarget&&!ghBusy){setGhOpen(!1);setGhMsg(null)}},style:{position:"fixed",inset:0,zIndex:99999,backgroundColor:"rgba(0,0,0,0.62)",backdropFilter:"blur(4px)",display:"flex",alignItems:"center",justifyContent:"center",padding:"16px"}},${rSym}.createElement("div",{className:"w-full max-w-md rounded-2xl border border-border bg-background text-foreground shadow-2xl p-5 flex flex-col gap-4",onMouseDown:ev=>ev.stopPropagation()},${rSym}.createElement("div",{className:"flex items-start justify-between gap-3"},${rSym}.createElement("div",{className:"flex items-center gap-2.5"},${rSym}.createElement("div",{className:"w-8 h-8 rounded-lg bg-secondary flex items-center justify-center text-foreground shrink-0"},ghIcon),${rSym}.createElement("div",{className:"flex flex-col"},${rSym}.createElement("h2",{className:"text-sm font-semibold text-foreground m-0"},"Install from GitHub"),${rSym}.createElement("span",{className:"text-xs text-muted-foreground"},"Install any plugin, SKILL.md, rules, or MCP server repo"))),${rSym}.createElement("button",{type:"button",disabled:ghBusy,onClick:()=>{setGhOpen(!1);setGhMsg(null)},className:"p-1 rounded-md text-muted-foreground hover:text-foreground hover:bg-secondary bg-transparent border-none cursor-pointer"},${rSym}.createElement(${ICON},{name:"close",size:16}))),${rSym}.createElement("div",{className:"flex flex-col gap-2"},${rSym}.createElement("label",{className:"text-xs font-medium text-foreground"},"Repository URL or owner/repo"),${rSym}.createElement("input",{ref:inputRef,type:"text",placeholder:"https://github.com/owner/repo",value:ghUrl,disabled:ghBusy,onChange:e=>setGhUrl(e.target.value),onKeyDown:e=>{if(e.key==="Enter")doGhInstall()},className:"w-full h-9 px-3 rounded-lg !bg-muted/60 !border !border-border text-xs font-mono text-foreground outline-none focus:!ring-1 focus:!ring-primary"}),${rSym}.createElement("div",{className:"text-[11px] text-muted-foreground leading-relaxed"},"Supports full repo URLs, ",${rSym}.createElement("code",{className:"px-1 py-0.5 rounded bg-muted font-mono"},"owner/repo"),", subfolder URLs (",${rSym}.createElement("code",{className:"px-1 py-0.5 rounded bg-muted font-mono"},".../tree/main/skills/my-skill"),"), or direct ",${rSym}.createElement("code",{className:"px-1 py-0.5 rounded bg-muted font-mono"},".zip")," links.")),ghMsg&&${rSym}.createElement("div",{className:"px-3 py-2 rounded-lg border text-xs "+(ghMsg.ok?"bg-emerald-500/10 border-emerald-500/30 text-emerald-400":"bg-red-500/10 border-red-500/30 text-red-400")},ghMsg.text),${rSym}.createElement("div",{className:"flex items-center justify-end gap-2 pt-1"},${rSym}.createElement(${BTN},{variant:"secondary",size:"sm",disabled:ghBusy,onClick:()=>{setGhOpen(!1);setGhMsg(null)}},"Cancel"),${rSym}.createElement(${BTN},{variant:"primary",size:"sm",disabled:ghBusy||!ghUrl.trim(),onClick:doGhInstall},ghBusy?"Downloading & Installing...":"Install Plugin")))))}`,
        80,
        750
    );

    // 5. Enable Model Usage / Quota in BOTH Model Selector ('View Usage' submenu) & Context Popover
    txt = replaceNearAnchor(txt, 'get("inputComponent")?.showModelUsage===!0', /[A-Za-z0-9_$]+\(\)\.get\("inputComponent"\)\?\.showModelUsage===!0/, "!0", 20, 10, true);
    txt = replaceNearAnchor(
        txt,
        '!pt-1 !pb-0 !text-foreground',
        /([A-Za-z0-9_$]+)\.createElement\([A-Za-z0-9_$]+,\{key:n\.displayName\|\|p\},n\.displayName&&\1\.createElement\([A-Za-z0-9_$]+,\{className:"!pt-1 !pb-0 !text-foreground"\},n\.displayName\),/,
        '$1.createElement("div",{key:n.displayName||p,className:"flex flex-col gap-0.5"},n.displayName&&$1.createElement("div",{className:"px-2 pt-1.5 pb-0.5 text-xs font-medium text-foreground"},n.displayName),',
        120,
        40
    );

    // 6. Bidirectional RTL / Persian + English Markdown & Input Fix
    txt = replaceNearAnchor(
        txt,
        'var f=c.split(" ");f.forEach(',
        /function ([A-Za-z0-9_$]+)\(a\)\{var b=\[\];a\.forEach\(\(c,d\)=>\{if\(typeof c!=="string"\)b\.push\(\{key:`node-\$\{d\}`,content:c\}\);else\{var f=c\.split\(" "\);f\.forEach\(\(g,h\)=>\{var k=h===f\.length-1;!g&&k\|\|b\.push\(\{key:`\$\{d\}-\$\{h\}`,content:k\?g:`\$\{g\} `\}\)\}\)\}\}\);return b\}/,
        'function $1(a){var _hasRtl=a.some(x=>typeof x==="string"&&/[\\u0590-\\u08FF\\uFB1D-\\uFDFF\\uFE70-\\uFEFF]/.test(x)),b=[];a.forEach((c,d)=>{if(typeof c!=="string"||_hasRtl)b.push({key:`node-${d}`,content:c});else{var f=c.split(" ");f.forEach((g,h)=>{var k=h===f.length-1;!g&&k||b.push({key:`${d}-${h}`,content:k?g:`${g} `})})}});return b}',
        130,
        140
    );
    txt = replaceNearAnchor(
        txt,
        '"whitespace-pre-wrap",b),style:{wordBreak:"break-word"}',
        /var ([A-Za-z0-9_$]+)=\(\{value:a,className:b,\.\.\.c\}\)=>([A-Za-z0-9_$]+)\.createElement\("code",\{(?:dir:"ltr",)?\.\.\.c,className:([A-Za-z0-9_$]+)\("whitespace-pre-wrap",b\),style:\{wordBreak:"break-word"\}\},a\);/,
        'var $1=({value:a,className:b,...c})=>$2.createElement("code",{...c,dir:"ltr",className:$3("whitespace-pre-wrap",b),style:{wordBreak:"break-word",unicodeBidi:"isolate",direction:"ltr"}},a);',
        100,
        20
    );
    txt = replaceNearAnchor(
        txt,
        'createElement("pre",{',
        /pre:\(\{node:a,\s*\.\.\.b\}\)=>\{a=([A-Za-z0-9_$]+)\(\);return ([A-Za-z0-9_$]+)\.createElement\("pre",\{(?:dir:"ltr",)?\.\.\.b,style:\{\.\.\.b\.style,\.\.\.a\}\}\)\}/,
        'pre:({node:a,...b})=>{a=$1();return $2.createElement("pre",{...b,dir:"ltr",style:{direction:"ltr",textAlign:"left",...b.style,...a}})}',
        60,
        60
    );
    txt = replaceNearAnchor(
        txt,
        'p:({node:a,...b})=>{var {animate:c,claimStaggerDelays:d}=',
        /p:\(\{node:a,\.\.\.b\}\)=>\{var \{animate:c,claimStaggerDelays:d\}=([A-Za-z0-9_$]+)\(\);return ([A-Za-z0-9_$]+)\.createElement\("p",\{\.\.\.b,className:([A-Za-z0-9_$]+)\(b\.className\)\},/,
        'p:({node:a,...b})=>{var {animate:c,claimStaggerDelays:d}=$1();return $2.createElement("p",{dir:"auto",...b,className:$3(b.className)},',
        10,
        140
    );
    txt = replaceNearAnchor(
        txt,
        '({node:c,...d})=>{var {animate:f,claimStaggerDelays:g}=',
        /const ([A-Za-z0-9_$]+)=a=>\{var b=\(\{node:c,\.\.\.d\}\)=>\{var \{animate:f,claimStaggerDelays:g\}=([A-Za-z0-9_$]+)\(\);return ([A-Za-z0-9_$]+)\.createElement\(a,\{\.\.\.d,className:([A-Za-z0-9_$]+)\(d\.className\)\},/,
        'const $1=a=>{var b=({node:c,...d})=>{var {animate:f,claimStaggerDelays:g}=$2();return $3.createElement(a,{dir:"auto",...d,className:$4(d.className)},',
        30,
        140
    );
    txt = txt
        .replace(
            'if(h)return A.createElement("li",{...f,style:{...f.style,...a},className:dj(f.className,"task-list-item")}',
            'if(h)return A.createElement("li",{dir:"auto",...f,style:{...f.style,...a},className:dj(f.className,"task-list-item")}'
        )
        .replace(
            'if(k){let {checkbox:m,inlineContent:n,sublists:p}=lVb(g);return A.createElement("li",{...f,style:{...f.style,\n...a},className:dj(f.className,"task-checked")}',
            'if(k){let {checkbox:m,inlineContent:n,sublists:p}=lVb(g);return A.createElement("li",{dir:"auto",...f,style:{...f.style,\n...a},className:dj(f.className,"task-checked")}'
        )
        .replace(
            'return A.createElement("li",{...f,style:{...f.style,...a},className:f.className},d(g))',
            'return A.createElement("li",{dir:"auto",...f,style:{...f.style,...a},className:f.className},d(g))'
        );
    txt = replaceNearAnchor(
        txt,
        'blockquote:({node:a,...b})=>{',
        /blockquote:\(\{node:a,\.\.\.b\}\)=>\{a=([A-Za-z0-9_$]+)\(\);return b\.className\?\.includes\("markdown-alert"\)\?([A-Za-z0-9_$]+)\.createElement\("blockquote",\{\.\.\.b,style:\{\.\.\.b\.style,\.\.\.a\}\}\):\2\.createElement\("blockquote",\{\.\.\.b,className:([A-Za-z0-9_$]+)\("relative my-2 pl-4 before:absolute before:inset-y-0 before:left-0 before:w-1 before:rounded-full before:bg-border",b\.className\),style:\{\.\.\.b\.style,\.\.\.a\}\}\)\}/,
        'blockquote:({node:a,...b})=>{a=$1();return b.className?.includes("markdown-alert")?$2.createElement("blockquote",{dir:"auto",...b,style:{...b.style,...a}}):$2.createElement("blockquote",{dir:"auto",...b,className:$3("relative my-2 pl-4 before:absolute before:inset-y-0 before:left-0 before:w-1 before:rounded-full before:bg-border",b.className),style:{...b.style,...a}})}',
        10,
        360
    );
    txt = replaceNearAnchor(
        txt,
        'th:({node:a,style:b,...c})=>',
        /th:\(\{node:a,style:b,\.\.\.c\}\)=>([A-Za-z0-9_$]+)\.createElement\("th",\{\.\.\.c,style:([A-Za-z0-9_$]+)\(b\)/,
        'th:({node:a,style:b,...c})=>$1.createElement("th",{dir:"auto",...c,style:$2(b)',
        10,
        80
    );
    txt = replaceNearAnchor(
        txt,
        'td:({node:a,style:b,...c})=>',
        /td:\(\{node:a,style:b,\.\.\.c\}\)=>([A-Za-z0-9_$]+)\.createElement\("td",\{\.\.\.c,style:([A-Za-z0-9_$]+)\(b\)/,
        'td:({node:a,style:b,...c})=>$1.createElement("td",{dir:"auto",...c,style:$2(b)',
        10,
        80
    );

    return txt;
}

// ---------------------------------------------------------------------------
// Live Patched UI Bundle Serving
// ---------------------------------------------------------------------------
function servePatchedUiBundle(lsPort, gwPort, res) {
    const cacheKey = `v4:${lsPort}:${gwPort}`;
    const sendWithLiveAuthHeader = (baseBuf) => {
        const dynPrefix = Buffer.from(`;if(typeof window!=="undefined")window.__AGY_CURRENT_AUTH_MODE__=${JSON.stringify(getCurrentAuthMode())};\n`, "utf8");
        res.writeHead(200, {
            "Content-Type": "application/javascript; charset=UTF-8",
            "Content-Length": dynPrefix.length + baseBuf.length,
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "no-store"
        });
        res.write(dynPrefix);
        res.end(baseBuf);
    };

    const cached = patchedBundleCache.get(cacheKey);
    if (cached) {
        return sendWithLiveAuthHeader(cached);
    }

    https.get({
        hostname: "127.0.0.1",
        port: lsPort,
        path: "/main.js",
        rejectUnauthorized: false
    }, (upRes) => {
        const chunks = [];
        upRes.on("data", d => chunks.push(d));
        upRes.on("end", () => {
            const gwBase = `https://127.0.0.1:${gwPort}`;
            let txt = patchUiMainBundleSource(Buffer.concat(chunks).toString("utf8"), gwBase);

            // Dynamic runtime toast + real-time EventSource telemetry stream + UI i18n MutationObserver + escape button + RTL/Bidi CSS
            txt += `\n;(function(){if(typeof window==="undefined")return;var _bootObs=function(){if(!document.body){setTimeout(_bootObs,80);return}try{if(window.__agyApplyDomLocalization&&window.__agyGetUiLanguage&&window.__agyGetUiLanguage()!=="en")window.__agyApplyDomLocalization(document.body);var mo=new MutationObserver(function(){if(window.__agyGetUiLanguage&&window.__agyGetUiLanguage()!=="en"&&window.__agyScheduleDomLocalization)window.__agyScheduleDomLocalization()});mo.observe(document.body,{childList:!0,subtree:!0,characterData:!0})}catch{}};_bootObs();try{var es=new EventSource("${gwBase}/__agy_telemetry_stream");es.onmessage=function(ev){try{var d=JSON.parse(ev.data);if(d&&typeof _agyEmitTel==="function")_agyEmitTel(d)}catch{}}}catch{}window.__agyShowToast=function(msg){try{var t=document.createElement("div");t.textContent=msg;t.style.cssText="position:fixed;top:44px;right:18px;z-index:999999;padding:8px 14px;border-radius:10px;font-size:12px;font-weight:500;background:#18181b;color:#fafafa;border:1px solid #3f3f46;box-shadow:0 8px 24px rgba(0,0,0,0.45);transition:opacity 0.3s ease;";document.body.appendChild(t);setTimeout(function(){t.style.opacity="0";setTimeout(function(){t.remove()},350)},3800)}catch{}};if(!document.getElementById("__agy_rtl_bidi_fix")){var st=document.createElement("style");st.id="__agy_rtl_bidi_fix";st.textContent='p[dir="auto"],li[dir="auto"],h1[dir="auto"],h2[dir="auto"],h3[dir="auto"],h4[dir="auto"],h5[dir="auto"],h6[dir="auto"],blockquote[dir="auto"]{text-align:start;}ul:has(>li:dir(rtl)),ol:has(>li:dir(rtl)){direction:rtl;padding-left:0!important;padding-right:1.25rem!important;}blockquote:dir(rtl){padding-left:0!important;padding-right:1rem!important;}blockquote:dir(rtl)::before{left:auto!important;right:0!important;}[contenteditable="true"],[data-lexical-editor] p,textarea:not(.font-mono){unicode-bidi:plaintext;text-align:start;}code:not(pre code){unicode-bidi:isolate;direction:ltr;}html[data-agy-lang="fa"] body,html[data-agy-lang="ar"] body{font-family:"Vazirmatn","Segoe UI",Tahoma,system-ui,sans-serif;}[data-agy-bidi="rtl"]{direction:rtl;unicode-bidi:isolate;text-align:left;}[data-agy-bidi="rtl"] code,[data-agy-bidi="rtl"] kbd{direction:ltr;unicode-bidi:isolate;display:inline-block;}';(document.head||document.documentElement).appendChild(st);}fetch("${gwBase}/__agy_auth/status").then(function(r){return r.json()}).then(function(j){if(j&&j.mode)window.__AGY_CURRENT_AUTH_MODE__=j.mode}).catch(function(){});setInterval(function(){try{var isOAuth=window.__AGY_CURRENT_AUTH_MODE__==="google_oauth";var bodyTxt=document.body?document.body.innerText:"";var isLoginScreen=isOAuth&&bodyTxt.includes("Sign in")&&!document.querySelector('[data-testid="settings-button"]');var existing=document.getElementById("__agy_back_to_apikey_btn");if(isLoginScreen&&!existing){var btn=document.createElement("button");btn.id="__agy_back_to_apikey_btn";btn.textContent="Switch to API Key Mode";btn.style.cssText="position:fixed;top:40px;right:18px;z-index:999999;padding:6px 14px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;background:#27272a;color:#fafafa;border:1px solid #3f3f46;box-shadow:0 4px 12px rgba(0,0,0,0.4);-webkit-app-region:no-drag;";btn.onclick=function(){btn.textContent="Switching...";fetch("${gwBase}/__agy_auth/switch_mode",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({mode:"apikey"})}).then(function(){window.__AGY_CURRENT_AUTH_MODE__="apikey";if(window.__agyCore&&window.__agyCore.authService)window.__agyCore.authService.checkCurrentAuthStatus();existing&&existing.remove();});};document.body.appendChild(btn);}else if(!isLoginScreen&&existing){existing.remove();}}catch(e){}},600);})();`;

            const outBuf = Buffer.from(txt, "utf8");
            patchedBundleCache.set(cacheKey, outBuf);
            sendWithLiveAuthHeader(outBuf);
        });
    }).on("error", (err) => {
        res.writeHead(502, { "Content-Type": "text/plain" });
        res.end("Failed to load UI bundle: " + err.message);
    });
}

// ---------------------------------------------------------------------------
// Native Google GenAI Forwarding + Multi-Key & Multi-Model Auto-Failover
// ---------------------------------------------------------------------------
function sanitizeTrailingModelTurn(genAiObj) {
    if (!genAiObj || !Array.isArray(genAiObj.contents) || genAiObj.contents.length === 0) return genAiObj;
    const isModelRole = (r) => String(r || "").toLowerCase() === "model";

    while (genAiObj.contents.length > 0 && isModelRole(genAiObj.contents[genAiObj.contents.length - 1]?.role)) {
        const last = genAiObj.contents[genAiObj.contents.length - 1];
        const parts = Array.isArray(last.parts) ? last.parts : [];
        const hasFnCall = parts.some(p => p && p.functionCall);
        // Ignore pure `thought: true` / `thoughtSignature` parts from interrupted streams!
        const hasVisibleContent = parts.some(
            p => p && !p.thought && ((typeof p.text === "string" && p.text.trim().length > 0) || p.inlineData || p.fileData)
        );
        if (!hasFnCall && !hasVisibleContent) {
            genAiObj.contents.pop();
            continue;
        }
        if (hasFnCall) {
            const respParts = parts
                .filter(p => p && p.functionCall)
                .map(p => ({
                    functionResponse: {
                        name: p.functionCall.name || "tool",
                        ...(p.functionCall.id ? { id: p.functionCall.id } : {}),
                        response: { result: "cancelled_or_resumed" }
                    }
                }));
            genAiObj.contents.push({ role: "user", parts: respParts });
        } else {
            genAiObj.contents.push({ role: "user", parts: [{ text: "Continue." }] });
        }
        break;
    }

    if (genAiObj.contents.length === 0) {
        genAiObj.contents.push({ role: "user", parts: [{ text: "Continue." }] });
    }
    return genAiObj;
}

function buildBodyForGoogleModel(rawJsonObj, targetModelId, selectedEffort) {
    if (!rawJsonObj) return null;
    const cloned = sanitizeTrailingModelTurn(JSON.parse(JSON.stringify(rawJsonObj)));
    cloned.generationConfig = cloned.generationConfig || {};
    cloned.generationConfig.thinkingConfig = cloned.generationConfig.thinkingConfig || {};
    cloned.generationConfig.thinkingConfig.includeThoughts = true;

    if (targetModelId.startsWith("gemma-4")) {
        delete cloned.generationConfig.thinkingConfig.thinkingBudget;
        cloned.generationConfig.thinkingConfig.thinkingLevel =
            (selectedEffort === "low" || selectedEffort === "medium") ? "MINIMAL" : "HIGH";
    } else {
        delete cloned.generationConfig.thinkingConfig.thinkingLevel;
        cloned.generationConfig.thinkingConfig.thinkingBudget =
            (selectedEffort && EFFORT_BUDGET_MAP[selectedEffort]) ? EFFORT_BUDGET_MAP[selectedEffort] : 8192;
    }
    return Buffer.from(JSON.stringify(cloned), "utf8");
}

function forwardToGoogleGenAi(req, res, candidateKeys, actionSuffix, candidateModels, parsedJson, rawFallbackBuf, selectedEffort, keyIdx = 0, modelIdx = 0, orderedKeysForModel = null) {
    const currentModel = candidateModels[modelIdx];
    const keysList = orderedKeysForModel || getOrderedApiKeysForModel("google", candidateKeys, currentModel);
    if (!keysList.length) {
        res.writeHead(401, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({
            error: {
                code: 401,
                message: "No Google Gemini API key configured in ~/.gemini/antigravity.json. Open Settings -> API Keys to add a key."
            }
        }));
    }

    const reqStartTs = Date.now();
    let firstTokenTs = 0;
    const currentKey = keysList[keyIdx];
    const targetPath = `/v1beta/models/${currentModel}${actionSuffix}`;
    const outBuf = parsedJson
        ? buildBodyForGoogleModel(parsedJson, currentModel, selectedEffort)
        : rawFallbackBuf;

    const cleanHeaders = { "x-goog-api-key": currentKey };
    if (req.headers["content-type"]) cleanHeaders["content-type"] = req.headers["content-type"];
    if (req.headers["accept"]) cleanHeaders["accept"] = req.headers["accept"];
    if (outBuf && outBuf.length > 0) cleanHeaders["content-length"] = outBuf.length;

    const upReq = createProxiedRequest(true, {
        hostname: "generativelanguage.googleapis.com",
        port: 443,
        path: targetPath,
        method: req.method,
        headers: cleanHeaders
    }, (upRes) => {
        const code = upRes.statusCode || 200;
        if (code === 429 || code === 503) {
            markApiKeyModelQuotaExhausted("google", currentKey, currentModel, String(code));
            if (keyIdx + 1 < keysList.length) {
                upRes.resume();
                return forwardToGoogleGenAi(req, res, candidateKeys, actionSuffix, candidateModels, parsedJson, rawFallbackBuf, selectedEffort, keyIdx + 1, modelIdx, keysList);
            }
            if (modelIdx + 1 < candidateModels.length) {
                upRes.resume();
                return forwardToGoogleGenAi(req, res, candidateKeys, actionSuffix, candidateModels, parsedJson, rawFallbackBuf, selectedEffort, 0, modelIdx + 1, null);
            }
        }

        res.writeHead(code, upRes.headers);
        let tailText = "";
        let liveGoogleTokensApprox = 0;
        const gUtf8Dec = new StringDecoder("utf8");
        upRes.on("data", (chunk) => {
            const chunkStr = gUtf8Dec.write(chunk);
            if (!firstTokenTs && code === 200) firstTokenTs = Date.now();
            res.write(chunk);
            if (code === 200) {
                tailText = (tailText + chunkStr).slice(-8192);
                // Extract exact live token counts from Google SSE chunk if present, else approximate from text delta length
                const mc = /"candidatesTokenCount"\s*:\s*(\d+)/g;
                const mt = /"thoughtsTokenCount"\s*:\s*(\d+)/g;
                let lc = 0, lt = 0, mx;
                while ((mx = mc.exec(tailText)) !== null) lc = Number(mx[1]);
                while ((mx = mt.exec(tailText)) !== null) lt = Number(mx[1]);
                if (lc + lt > 0) {
                    liveGoogleTokensApprox = lc + lt;
                } else {
                    const txtRe = /"text"\s*:\s*"((?:\\.|[^"\\])*)"/g;
                    while ((mx = txtRe.exec(chunkStr)) !== null) {
                        liveGoogleTokensApprox += Math.max(1, Math.round(mx[1].length / 4));
                    }
                }
                if (liveGoogleTokensApprox > 0) {
                    tickStreamingTelemetry({
                        modelId: currentModel,
                        providerName: "Google Gemini",
                        requestStartTs: reqStartTs,
                        firstTokenTs,
                        streamedTokensSoFar: liveGoogleTokensApprox
                    });
                }
            }
        });
        upRes.on("end", () => {
            if (code === 200) {
                const mPrompt = /"promptTokenCount"\s*:\s*(\d+)/g;
                const mCand = /"candidatesTokenCount"\s*:\s*(\d+)/g;
                const mThought = /"thoughtsTokenCount"\s*:\s*(\d+)/g;
                let lastPrompt = 0, lastCand = 0, lastThought = 0, m;
                while ((m = mPrompt.exec(tailText)) !== null) lastPrompt = Number(m[1]);
                while ((m = mCand.exec(tailText)) !== null) lastCand = Number(m[1]);
                while ((m = mThought.exec(tailText)) !== null) lastThought = Number(m[1]);
                const pTok = lastPrompt || Math.round((outBuf ? outBuf.length : 0) / 4);
                const cTok = (lastCand + lastThought) || 64;
                recordModelUsage(currentModel, pTok);
                recordRequestTelemetry({
                    modelId: currentModel,
                    providerName: "Google Gemini",
                    requestStartTs: reqStartTs,
                    firstTokenTs: firstTokenTs || Date.now(),
                    endTs: Date.now(),
                    promptTokens: pTok,
                    completionTokens: cTok
                });
            }
            res.end();
        });
    });

    upReq.on("error", (err) => {
        if (!res.headersSent) {
            res.writeHead(502, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: { code: 502, message: err.message } }));
        }
    });

    upReq.end(outBuf);
}

async function handlePlusSettingsRequest(urlPath, req, res, rawBodyBuf) {
    const corsHeaders = {
        "Content-Type": "application/json; charset=UTF-8",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type"
    };
    if (req.method === "OPTIONS") {
        res.writeHead(204, corsHeaders);
        return res.end();
    }
    const buildState = () => ({
        settings: loadPlusSettings(),
        cooldowns: getQuotaCooldownsOverview(),
        telemetry: getTelemetrySnapshot()
    });

    if (urlPath === "/__agy_plus/get") {
        res.writeHead(200, corsHeaders);
        return res.end(JSON.stringify(buildState()));
    }

    let payload = {};
    try { payload = JSON.parse(rawBodyBuf.toString("utf8") || "{}"); } catch {}

    if (urlPath === "/__agy_plus/save" && req.method === "POST") {
        const prev = loadPlusSettings();
        const next = savePlusSettings(payload);
        const proxyChanged = prev.proxyEnabled !== next.proxyEnabled || prev.proxyUrl !== next.proxyUrl;
        if (proxyChanged && _lsHotRestartCallback) {
            try { await _lsHotRestartCallback(); } catch {}
        }
        res.writeHead(200, corsHeaders);
        return res.end(JSON.stringify({ success: true, proxyReloaded: proxyChanged, ...buildState() }));
    }

    if (urlPath === "/__agy_plus/test_proxy" && req.method === "POST") {
        const check = await testProxyConnectionLive(payload.proxyUrl);
        res.writeHead(200, corsHeaders);
        return res.end(JSON.stringify(check));
    }

    if (urlPath === "/__agy_plus/clear_cooldowns" && req.method === "POST") {
        clearAllQuotaCooldowns();
        res.writeHead(200, corsHeaders);
        return res.end(JSON.stringify({ success: true, ...buildState() }));
    }

    if (urlPath === "/__agy_plus/reset_telemetry" && req.method === "POST") {
        resetTelemetrySnapshot();
        res.writeHead(200, corsHeaders);
        return res.end(JSON.stringify({ success: true, ...buildState() }));
    }

    res.writeHead(404, corsHeaders);
    res.end(JSON.stringify({ error: "Not found" }));
}

function startServerOnPort(cert, key, portToTry) {
    return new Promise((resolve, reject) => {
        const server = https.createServer({ cert, key }, (req, res) => {
            const urlPath = req.url || "/";
            if (urlPath === "/__agy_health") {
                res.writeHead(200, { "Content-Type": "application/json" });
                return res.end(JSON.stringify({ ok: true }));
            }
            if (urlPath.startsWith("/__agy_telemetry_stream")) {
                return subscribeTelemetrySse(res);
            }
            if (urlPath.startsWith("/__agy_i18n/get")) {
                const u = new URL(urlPath, "https://127.0.0.1");
                const lang = u.searchParams.get("lang") || "en";
                const pack = getLocalePackByCode(lang);
                res.writeHead(200, {
                    "Content-Type": "application/json; charset=UTF-8",
                    "Access-Control-Allow-Origin": "*",
                    "Cache-Control": "no-store"
                });
                return res.end(JSON.stringify(pack));
            }
            if (urlPath === "/__agy_i18n/languages") {
                res.writeHead(200, {
                    "Content-Type": "application/json; charset=UTF-8",
                    "Access-Control-Allow-Origin": "*"
                });
                return res.end(JSON.stringify({ languages: SUPPORTED_LANGUAGES }));
            }
            if (urlPath.startsWith("/__agy_quota")) {
                res.writeHead(200, {
                    "Content-Type": "application/json; charset=UTF-8",
                    "Access-Control-Allow-Origin": "*",
                    "Cache-Control": "no-store"
                });
                return res.end(JSON.stringify(buildLiveQuotaSummaryResponse()));
            }
            if (urlPath.startsWith("/__agy_ui_main.js")) {
                const u = new URL(urlPath, "https://127.0.0.1");
                const lsPort = parseInt(u.searchParams.get("lsPort") || "0", 10);
                if (lsPort > 0) {
                    return servePatchedUiBundle(lsPort, boundGatewayPort, res);
                }
            }

            const chunks = [];
            req.on("data", c => chunks.push(c));
            req.on("end", () => {
                const bodyBuf = Buffer.concat(chunks);

                if (urlPath.startsWith("/__agy_auth/")) {
                    return void handleAuthModeRequest(urlPath.split("?")[0], req, res, bodyBuf);
                }
                if (urlPath.startsWith("/__agy_plus/")) {
                    return void handlePlusSettingsRequest(urlPath.split("?")[0], req, res, bodyBuf);
                }
                if (urlPath.startsWith("/__agy_config/")) {
                    return void handleAgyConfigRequest(urlPath.split("?")[0], req, res, bodyBuf);
                }
                if (urlPath.startsWith("/__agy_plugins/")) {
                    return void handlePluginManagerRequest(urlPath.split("?")[0], req, res, bodyBuf);
                }

                // Match /v1beta/models/<id>(-low|-medium|-high|-max)?:(streamGenerateContent|generateContent)
                const modelActionMatch = /\/models\/(.+?)(?:-(low|medium|high|max))?(:[a-zA-Z]+(?:\?.*)?)$/i.exec(urlPath);
                if (modelActionMatch && /GenerateContent/i.test(modelActionMatch[3])) {
                    const rawBaseId = modelActionMatch[1];
                    const lookupKey = rawBaseId.toLowerCase();
                    const selectedEffort = modelActionMatch[2] ? modelActionMatch[2].toLowerCase() : null;
                    const actionSuffix = modelActionMatch[3];
                    const isStreaming = /streamGenerateContent/i.test(actionSuffix);

                    // Check exact match first, or full unstripped ID if model didn't have effort suffix
                    const fullUnstrippedKey = selectedEffort ? `${lookupKey}-${selectedEffort}` : lookupKey;
                    const route = modelRouteTable.get(fullUnstrippedKey) || modelRouteTable.get(lookupKey);

                    let parsedJson = null;
                    if (bodyBuf.length > 0) {
                        try { parsedJson = JSON.parse(bodyBuf.toString("utf8")); } catch {}
                    }

                    if (route && route.protocol === "anthropic-messages") {
                        return forwardToAnthropicMessagesProvider(req, res, route, parsedJson, isStreaming, selectedEffort, 0);
                    }
                    if (route && (route.protocol === "openai-compatible" || route.protocol === "azure-openai")) {
                        return forwardToOpenAiCompatibleProvider(req, res, route, parsedJson, isStreaming, 0);
                    }

                    const googleKeys = route ? route.apiKeys : [getActiveApiKey()].filter(Boolean);
                    const upstreamGoogleModel = route ? route.upstreamModelId : lookupKey;
                    const candidateModels = [upstreamGoogleModel];
                    for (const fb of FAILOVER_GOOGLE_MODELS) {
                        if (!candidateModels.includes(fb)) candidateModels.push(fb);
                    }

                    return forwardToGoogleGenAi(
                        req, res, googleKeys, actionSuffix, candidateModels, parsedJson, bodyBuf, selectedEffort, 0, 0
                    );
                }

                // Tier 3 Gateway Model Discovery fallback (enables non-root Linux & macOS discovery automatically)
                const cleanQueryPath = urlPath.split("?")[0];
                if (req.method === "GET" && (cleanQueryPath === "/v1beta/models" || cleanQueryPath === "/v1/models")) {
                    return void buildDynamicAdminSettings(boundGatewayPort).then((cfg) => {
                        const list = Array.isArray(cfg?.models?.list) ? cfg.models.list : [];
                        res.writeHead(200, { "Content-Type": "application/json; charset=UTF-8" });
                        if (cleanQueryPath === "/v1beta/models") {
                            res.end(JSON.stringify({
                                models: list.map(m => ({
                                    name: `models/${m.modelId}`,
                                    displayName: m.displayName || m.modelId,
                                    inputTokenLimit: m.maxTokens || 1048576,
                                    outputTokenLimit: m.maxOutputTokens || 32768,
                                    thinking: !!m.supportsThinking,
                                    supportedGenerationMethods: ["generateContent", "streamGenerateContent"]
                                }))
                            }));
                        } else {
                            res.end(JSON.stringify({
                                object: "list",
                                data: list.map(m => ({
                                    id: m.modelId,
                                    object: "model",
                                    created: 1700000000,
                                    owned_by: "antigravity-gateway"
                                }))
                            }));
                        }
                    }).catch((err) => {
                        res.writeHead(500, { "Content-Type": "application/json" });
                        res.end(JSON.stringify({ error: { code: 500, message: err.message } }));
                    });
                }

                // Other Google GenAI REST calls (e.g. :countTokens)
                if (/:countTokens\b/i.test(urlPath)) {
                    const mCount = /\/models\/(.+?)(?:-(low|medium|high|max))?:countTokens/i.exec(urlPath);
                    const cKey = mCount ? mCount[1].toLowerCase() : "";
                    const cFull = (mCount && mCount[2]) ? `${cKey}-${mCount[2].toLowerCase()}` : cKey;
                    const cRoute = modelRouteTable.get(cFull) || modelRouteTable.get(cKey);
                    const activeGoogleKey = (cRoute && cRoute.protocol === "google-genai" && cRoute.apiKeys[0]) || "";
                    if (!activeGoogleKey || (cRoute && cRoute.protocol !== "google-genai")) {
                        const approxTokens = Math.max(1, Math.round(bodyBuf.length / 3.8));
                        res.writeHead(200, { "Content-Type": "application/json; charset=UTF-8" });
                        return res.end(JSON.stringify({ totalTokens: approxTokens }));
                    }
                }

                const activeKey = getActiveApiKey();
                if (!activeKey) {
                    res.writeHead(401, { "Content-Type": "application/json" });
                    return res.end(JSON.stringify({
                        error: { code: 401, message: "No API key configured in ~/.gemini/antigravity.json." }
                    }));
                }
                const cleanUrlPath = urlPath.replace(
                    /\/models\/([a-z0-9\.\-_]+?)-(low|medium|high|max)(:[a-zA-Z]+)/i,
                    (_m, bId, _eff, act) => `/models/${bId}${act}`
                );
                let outOtherBuf = bodyBuf;
                if (bodyBuf.length > 0 && req.method === "POST") {
                    try {
                        const pj = JSON.parse(bodyBuf.toString("utf8"));
                        if (pj && Array.isArray(pj.contents)) {
                            outOtherBuf = Buffer.from(JSON.stringify(sanitizeTrailingModelTurn(pj)), "utf8");
                        }
                    } catch {}
                }
                const cleanHeaders = { "x-goog-api-key": activeKey };
                if (req.headers["content-type"]) cleanHeaders["content-type"] = req.headers["content-type"];
                if (req.headers["accept"]) cleanHeaders["accept"] = req.headers["accept"];
                if (outOtherBuf.length > 0) cleanHeaders["content-length"] = outOtherBuf.length;

                const upReq = createProxiedRequest(true, {
                    hostname: "generativelanguage.googleapis.com",
                    port: 443,
                    path: cleanUrlPath,
                    method: req.method,
                    headers: cleanHeaders
                }, (upRes) => {
                    res.writeHead(upRes.statusCode || 200, upRes.headers);
                    upRes.pipe(res);
                });
                upReq.on("error", (err) => {
                    if (!res.headersSent) {
                        res.writeHead(502, { "Content-Type": "application/json" });
                        res.end(JSON.stringify({ error: { code: 502, message: err.message } }));
                    }
                });
                upReq.end(outOtherBuf);
            });
        });

        server.once("error", (err) => reject(err));

        server.listen(portToTry, "127.0.0.1", () => {
            const addr = server.address();
            const boundPort = typeof addr === "object" && addr ? addr.port : portToTry;
            boundGatewayPort = boundPort;
            console.log(`[GatewayForwarder] Active on https://localhost:${boundPort} (Config: ${AGY_JSON_CONFIG_PATH})`);
            resolve(boundPort);
        });
    });
}

function ensureGatewayForwarder() {
    if (activePortPromise) return activePortPromise;
    activePortPromise = (async () => {
        ensureAgyConfigFile();
        const { cert, key } = ensureLocalTlsCertificates();
        let port;
        try {
            port = await startServerOnPort(cert, key, DEFAULT_PORT);
        } catch {
            port = await startServerOnPort(cert, key, 0);
        }
        if (getCurrentAuthMode() === "google_oauth") {
            removeAdminSettingsFilesForOAuthMode();
        } else {
            await syncAdminSettingsFiles(port);
        }

        // Auto-watch ~/.gemini/antigravity.json so external edits in VS Code / Notepad sync live!
        fs.watchFile(AGY_JSON_CONFIG_PATH, { interval: 1500 }, () => {
            if (getCurrentAuthMode() === "apikey") {
                void syncAdminSettingsFiles(port).catch(() => {});
            }
        });

        return { port, certPath: CERT_PATH };
    })();
    return activePortPromise;
}
