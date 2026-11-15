"use strict";

/**
 * Surgical, version-resilient, idempotent JavaScript patcher for Antigravity's Electron layer.
 */

const fs = require("fs");
const path = require("path");

const GATEWAY_SOURCE_FILE = path.join(__dirname, "gatewayForwarder.js");
const NETWORK_SOURCE_FILE = path.join(__dirname, "networkAndPlugins.js");
const LOCALIZATION_SOURCE_FILE = path.join(__dirname, "uiLocalization.js");
const LOCALES_JSON_FILE = path.join(__dirname, "locales.json");

function patchMenuJs(distDir) {
    const filePath = path.join(distDir, "menu.js");
    if (!fs.existsSync(filePath)) return { file: "dist/menu.js", status: "skipped" };
    const src = fs.readFileSync(filePath, "utf8");
    if (src.includes("if (false && (0, utils_1.isMacOS)())")) {
        return { file: "dist/menu.js", status: "already_patched" };
    }
    const updated = src.replace(
        /(Check for Updates[\s\S]{0,120}?)if\s*\(\(0,\s*utils_1\.isMacOS\)\(\)\)/,
        "$1if (false && (0, utils_1.isMacOS)())"
    );
    if (updated !== src) {
        fs.writeFileSync(filePath, updated, "utf8");
        return { file: "dist/menu.js", status: "patched" };
    }
    return { file: "dist/menu.js", status: "unchanged" };
}

function patchDebugConsoleJs(distDir) {
    const filePath = path.join(distDir, "debugConsole.js");
    if (!fs.existsSync(filePath)) return { file: "dist/debugConsole.js", status: "skipped" };

    let src = fs.readFileSync(filePath, "utf8");
    const updated = src.replace(
        /function\s+isDebugConsoleEnabled\s*\(\)\s*\{[\s\S]*?\n\}/,
        "function isDebugConsoleEnabled() {\n    return true;\n}"
    );
    if (updated !== src) {
        fs.writeFileSync(filePath, updated, "utf8");
        return { file: "dist/debugConsole.js", status: "patched" };
    }
    return { file: "dist/debugConsole.js", status: "already_patched" };
}

function patchMainJs(distDir, { keepAutoUpdater = false } = {}) {
    const filePath = path.join(distDir, "main.js");
    if (!fs.existsSync(filePath)) return { file: "dist/main.js", status: "skipped" };
    if (keepAutoUpdater) return { file: "dist/main.js", status: "skipped" };

    let src = fs.readFileSync(filePath, "utf8");
    if (src.includes("// (0, updater_1.initAutoUpdater)")) {
        return { file: "dist/main.js", status: "already_patched" };
    }
    const updated = src.replace(
        /^\s*\(0,\s*updater_1\.initAutoUpdater\)\([^)]*\);/m,
        "    // (0, updater_1.initAutoUpdater)(HEADLESS, settingsService);"
    );
    if (updated !== src) {
        fs.writeFileSync(filePath, updated, "utf8");
        return { file: "dist/main.js", status: "patched" };
    }
    return { file: "dist/main.js", status: "unchanged" };
}

function patchWslJs(distDir) {
    const filePath = path.join(distDir, "wsl.js");
    if (!fs.existsSync(filePath)) return { file: "dist/wsl.js", status: "skipped" };

    let src = fs.readFileSync(filePath, "utf8");
    const updated = src.replace(
        /async\s+function\s+listWslDistros\s*\(\)\s*\{\s*const\s+output\s*=\s*await\s+execWsl\(\['--list',\s*'--verbose'\]\);\s*return\s+parseWslListOutput\(output\)\.filter\(isSupportedDevDistro\);\s*\}/,
        [
            "async function listWslDistros() {",
            "    try {",
            "        const output = await execWsl(['--list', '--verbose']);",
            "        return parseWslListOutput(output).filter(isSupportedDevDistro);",
            "    }",
            "    catch {",
            "        return [];",
            "    }",
            "}"
        ].join("\n")
    );
    if (updated !== src) {
        fs.writeFileSync(filePath, updated, "utf8");
        return { file: "dist/wsl.js", status: "patched" };
    }
    return { file: "dist/wsl.js", status: "already_patched" };
}

function patchUtilsJs(distDir) {
    const filePath = path.join(distDir, "utils.js");
    if (!fs.existsSync(filePath)) return { file: "dist/utils.js", status: "skipped" };

    let src = fs.readFileSync(filePath, "utf8");
    let changed = false;

    // 1. Force classic single BrowserWindow renderer instead of WCV split-window gate
    const nextWcv = src.replace(
        /function\s+isWcvBrowserWindowEnabled\s*\(\)\s*\{[\s\S]*?\n\}\r?\nfunction\s+isPopupWindow/,
        "function isWcvBrowserWindowEnabled() {\n    return false;\n}\nfunction isPopupWindow"
    );
    if (nextWcv !== src) {
        src = nextWcv;
        changed = true;
    }

    // 2. Forward renderer console logs when missing
    if (!src.includes("console.log(`[Renderer] ${message}`)")) {
        const nextLog = src.replace(
            /(registerWindowWebContents\(win,\s*hubContents\);)/,
            "$1\n    hubContents.on('console-message', (_event, _level, message) => {\n        console.log(`[Renderer] ${message}`);\n    });"
        );
        if (nextLog !== src) {
            src = nextLog;
            changed = true;
        }
    }

    if (changed) {
        fs.writeFileSync(filePath, src, "utf8");
        return { file: "dist/utils.js", status: "patched" };
    }
    return { file: "dist/utils.js", status: "already_patched" };
}

function patchLanguageServerJs(distDir) {
    const filePath = path.join(distDir, "languageServer.js");
    if (!fs.existsSync(filePath)) {
        throw new Error(`Required file missing: ${filePath}`);
    }

    let src = fs.readFileSync(filePath, "utf8");
    let changed = false;

    // 1. Require gatewayForwarder
    if (!src.includes('require("./gatewayForwarder")')) {
        const nextReq = src.replace(
            /(const\s+utils_1\s*=\s*require\("\.\/utils"\);)/,
            '$1\nconst gatewayForwarder_1 = require("./gatewayForwarder");'
        );
        if (nextReq === src) {
            throw new Error("Could not anchor gatewayForwarder import in dist/languageServer.js");
        }
        src = nextReq;
        changed = true;
    }

    // 2. Cache login-shell env so LS hot-swaps finish in ~300ms instead of re-spawning login shell
    if (!src.includes("cachedResolvedShellEnv")) {
        const nextShell = src.replace(
            /let\s+prefetchedShellEnv;[\s\S]*?function\s+takeShellEnv\s*\(\)\s*\{[\s\S]*?\n\}/,
            [
                "let prefetchedShellEnv;",
                "let cachedResolvedShellEnv = null;",
                "function prefetchShellEnv() {",
                "    prefetchedShellEnv ?? (prefetchedShellEnv = (0, shell_env_1.shellEnv)().then((env) => {",
                "        cachedResolvedShellEnv = env;",
                "        return env;",
                "    }));",
                "}",
                "function takeShellEnv() {",
                "    if (cachedResolvedShellEnv) {",
                "        return Promise.resolve(cachedResolvedShellEnv);",
                "    }",
                "    const envPromise = prefetchedShellEnv ?? (0, shell_env_1.shellEnv)();",
                "    return envPromise.then((env) => {",
                "        cachedResolvedShellEnv = env;",
                "        return env;",
                "    });",
                "}"
            ].join("\n")
        );
        if (nextShell !== src) {
            src = nextShell;
            changed = true;
        }
    }

    // 3. Parallel gateway boot + pre-spawn auth environment sync inside startLanguageServer
    if (!src.includes("ensureGatewayForwarder")) {
        const nextStart = src.replace(
            /const\s+loginShellEnv\s*=\s*await\s+takeShellEnv\(\);/,
            [
                "const [loginShellEnv, gw] = await Promise.all([",
                "        takeShellEnv(),",
                "        (0, gatewayForwarder_1.ensureGatewayForwarder)()",
                "    ]);",
                "    await (0, gatewayForwarder_1.prepareAuthEnvironmentBeforeSpawn)(gw.port);"
            ].join("\n")
        );
        if (nextStart === src) {
            throw new Error("Could not anchor takeShellEnv() in dist/languageServer.js");
        }
        src = nextStart;
        changed = true;
    } else if (!src.includes("prepareAuthEnvironmentBeforeSpawn")) {
        const nextPrep = src.replace(
            /(const\s+\[loginShellEnv,\s*gw\]\s*=\s*await\s+Promise\.all\(\[[\s\S]*?\]\);)/,
            "$1\n    await (0, gatewayForwarder_1.prepareAuthEnvironmentBeforeSpawn)(gw.port);"
        );
        if (nextPrep !== src) {
            src = nextPrep;
            changed = true;
        }
    }

    // 4. Dynamic OAuth slot app_data_dir + API Key vs Google OAuth CLI flags
    if (!src.includes("effectiveAppDataDir")) {
        const nextArgs = src.replace(
            /const\s+args\s*=\s*\[\s*'--standalone',[\s\S]*?'--enable_sidecars',\s*\];/,
            [
                "const authMode = (0, gatewayForwarder_1.getCurrentAuthMode)();",
                "        const effectiveAppDataDir = authMode === 'google_oauth'",
                "            ? (0, gatewayForwarder_1.getActiveOAuthAppDataDir)((0, paths_1.getAppDataDirName)())",
                "            : (0, paths_1.getAppDataDirName)();",
                "        const args = [",
                "            '--standalone',",
                "            '--override_ide_name',",
                "            'antigravity',",
                "            '--subclient_type',",
                "            'hub',",
                "            '--override_ide_version',",
                "            electron_1.app.getVersion(),",
                "            '--override_user_agent_name',",
                "            'antigravity',",
                "            '--https_server_port',",
                "            String(port),",
                "            '--csrf_token',",
                "            csrf,",
                "            '--app_data_dir',",
                "            effectiveAppDataDir,",
                "        ];",
                "        if (authMode === 'apikey') {",
                "            args.push('--api_server_url', 'https://generativelanguage.googleapis.com');",
                "        }",
                "        else {",
                "            args.push(",
                "                '--api_server_url',",
                "                'https://generativelanguage.googleapis.com',",
                "                '--cloud_code_endpoint',",
                "                'https://daily-cloudcode-pa.googleapis.com'",
                "            );",
                "        }",
                "        args.push('--enable_sidecars');"
            ].join("\n")
        );
        if (nextArgs === src) {
            throw new Error("Could not anchor LS CLI args array in dist/languageServer.js");
        }
        src = nextArgs;
        changed = true;
    }

    // 5. Inject Gateway env vars in API Key mode (cleanly stripped + ANTIGRAVITY_VSCODE_HOST=1 in OAuth mode)
    if (!src.includes("AGY_LLM_GATEWAY_WIRE_PROTOCOL")) {
        const nextEnv = src.replace(
            /(const\s+env\s*=\s*\{\s*\.\.\.process\.env,\s*\.\.\.loginShellEnv\s*\};)/,
            [
                "$1",
                "        delete env['AGY_LLM_GATEWAY_API_KEY'];",
                "        delete env['AGY_LLM_GATEWAY_HEADERS'];",
                "        if (authMode === 'apikey') {",
                "            const apiKey = (0, gatewayForwarder_1.getActiveApiKey)();",
                "            env['AGY_LLM_GATEWAY_URL'] = `https://localhost:${gw.port}`;",
                "            env['AGY_LLM_GATEWAY_WIRE_PROTOCOL'] = 'genai';",
                "            env['AGY_LLM_GATEWAY_CA_CERT'] = gw.certPath;",
                "            env['GEMINI_API_KEY'] = apiKey;",
                "            env['GOOGLE_API_KEY'] = apiKey;",
                "        }",
                "        else {",
                "            delete env['AGY_LLM_GATEWAY_URL'];",
                "            delete env['AGY_LLM_GATEWAY_WIRE_PROTOCOL'];",
                "            delete env['AGY_LLM_GATEWAY_CA_CERT'];",
                "            delete env['GEMINI_API_KEY'];",
                "            delete env['GOOGLE_API_KEY'];",
                "            env['ANTIGRAVITY_VSCODE_HOST'] = '1';",
                "        }"
            ].join("\n")
        );
        if (nextEnv === src) {
            throw new Error("Could not anchor LS env block in dist/languageServer.js");
        }
        src = nextEnv;
        changed = true;
    } else if (!src.includes("env['ANTIGRAVITY_VSCODE_HOST'] = '1'")) {
        const nextOAuthEnv = src.replace(
            /delete\s+env\['AGY_LLM_GATEWAY_CA_CERT'\];/,
            [
                "delete env['AGY_LLM_GATEWAY_CA_CERT'];",
                "            delete env['GEMINI_API_KEY'];",
                "            delete env['GOOGLE_API_KEY'];",
                "            env['ANTIGRAVITY_VSCODE_HOST'] = '1';"
            ].join("\n")
        );
        if (nextOAuthEnv !== src) {
            src = nextOAuthEnv;
            changed = true;
        }
    }

    // 5b. Route OAuth URLs directly to Chrome with `prompt=select_account`
    if (!src.includes("openOAuthUrlInChrome")) {
        const nextOpen = src.replace(
            /void\s+electron_1\.shell\.openExternal\(openUrl\);/,
            "(0, gatewayForwarder_1.openOAuthUrlInChrome)(openUrl);"
        );
        if (nextOpen !== src) {
            src = nextOpen;
            changed = true;
        }
    }

    // 5c. Propagate built-in HTTP/HTTPS/SOCKS5 proxy settings to Language Server (with localhost NO_PROXY)
    if (!src.includes("getProxyEnvForLanguageServer")) {
        const nextProxyEnv = src.replace(
            /(delete\s+env\['AGY_LLM_GATEWAY_HEADERS'\];)/,
            [
                "$1",
                "        const proxyCfg = (0, gatewayForwarder_1.getProxyEnvForLanguageServer)();",
                "        if (proxyCfg && proxyCfg.enabled && proxyCfg.proxyUrl) {",
                "            env['HTTPS_PROXY'] = proxyCfg.proxyUrl;",
                "            env['HTTP_PROXY'] = proxyCfg.proxyUrl;",
                "            env['ALL_PROXY'] = proxyCfg.proxyUrl;",
                "            env['NO_PROXY'] = proxyCfg.noProxy;",
                "            env['no_proxy'] = proxyCfg.noProxy;",
                "        }"
            ].join("\n")
        );
        if (nextProxyEnv !== src) {
            src = nextProxyEnv;
            changed = true;
        }
    }

    // 6. Zero-reload same-port Hot-Swap engine (~300ms OAuth <-> API Key & live plugin discovery)
    if (!src.includes("hotRestartLanguageServer")) {
        const nextHot = src.replace(
            /async\s+function\s+startAndMonitorLanguageServer\s*\(([^)]*)\)\s*\{/,
            [
                "let _savedStartArgs = null;",
                "async function fastKillLanguageServer() {",
                "    setIntentionalTermination(true);",
                "    const proc = getLsProcess();",
                "    if (!proc) return;",
                "    const pid = proc.pid;",
                "    const exitPromise = new Promise((resolve) => {",
                "        proc.once('exit', () => resolve());",
                "    });",
                "    try {",
                "        if (process.platform === 'win32' && pid !== undefined) {",
                "            process.kill(pid, 'SIGKILL');",
                "        } else {",
                "            proc.kill('SIGTERM');",
                "        }",
                "    } catch {}",
                "    await Promise.race([",
                "        exitPromise,",
                "        new Promise((resolve) => setTimeout(resolve, 400)),",
                "    ]);",
                "    clearLsProcess();",
                "}",
                "async function hotRestartLanguageServer() {",
                "    if (!_savedStartArgs) {",
                "        return { restarted: false, samePort: false };",
                "    }",
                "    const { csrf, options } = _savedStartArgs;",
                "    const prevPort = _lsPort;",
                "    await fastKillLanguageServer();",
                "    setIntentionalTermination(false);",
                "    let handle;",
                "    try {",
                "        handle = await startLanguageServer(prevPort > 0 ? prevPort : 0, csrf, options);",
                "    } catch {",
                "        handle = await startLanguageServer(0, csrf, options);",
                "    }",
                "    _lsPort = handle.port;",
                "    const samePort = prevPort > 0 && _lsPort === prevPort;",
                "    if (!samePort && options.onPortChanged) {",
                "        options.onPortChanged(_lsPort);",
                "    }",
                "    monitorLsCrashInternal(handle, _lsPort, csrf, options);",
                "    return { restarted: true, samePort, port: _lsPort };",
                "}",
                "(0, gatewayForwarder_1.registerLsHotRestart)(hotRestartLanguageServer);",
                "async function startAndMonitorLanguageServer($1) {",
                "    _savedStartArgs = { port, csrf, options };"
            ].join("\n")
        );
        if (nextHot === src) {
            throw new Error("Could not anchor startAndMonitorLanguageServer in dist/languageServer.js");
        }
        src = nextHot;
        changed = true;
    }

    // 7. Redirect /main.js bundle through Gateway UI Patcher inside setupLocalCertTrust()
    if (!src.includes("__agy_ui_main.js")) {
        const nextCert = src.replace(
            /function\s+setupLocalCertTrust\s*\(\)\s*\{([\s\S]*?)\n\}/,
            [
                "let _uiRedirectRegistered = false;",
                "function setupLocalCertTrust() {$1",
                "    if (!_uiRedirectRegistered) {",
                "        _uiRedirectRegistered = true;",
                "        electron_1.session.defaultSession.webRequest.onBeforeRequest(",
                "            { urls: ['https://127.0.0.1:*/main.js*'] },",
                "            (details, callback) => {",
                "                try {",
                "                    const parsed = new URL(details.url);",
                "                    const gwPort = (0, gatewayForwarder_1.getBoundGatewayPort)();",
                "                    if (parsed.port && Number(parsed.port) !== gwPort) {",
                "                        return callback({",
                "                            redirectURL: `https://127.0.0.1:${gwPort}/__agy_ui_main.js?lsPort=${parsed.port}`,",
                "                        });",
                "                    }",
                "                }",
                "                catch {}",
                "                callback({});",
                "            }",
                "        );",
                "    }",
                "}"
            ].join("\n")
        );
        if (nextCert === src) {
            throw new Error("Could not anchor setupLocalCertTrust in dist/languageServer.js");
        }
        src = nextCert;
        changed = true;
    }

    if (changed) {
        fs.writeFileSync(filePath, src, "utf8");
        return { file: "dist/languageServer.js", status: "patched" };
    }
    return { file: "dist/languageServer.js", status: "already_patched" };
}

function applyAllJsPatches(appDir, options = {}) {
    const distDir = path.join(appDir, "dist");
    if (!fs.existsSync(distDir)) {
        throw new Error(`Electron dist directory not found: ${distDir}`);
    }

    // Always install latest sanitized gatewayForwarder.js, networkAndPlugins.js, uiLocalization.js & locales.json
    fs.copyFileSync(GATEWAY_SOURCE_FILE, path.join(distDir, "gatewayForwarder.js"));
    fs.copyFileSync(NETWORK_SOURCE_FILE, path.join(distDir, "networkAndPlugins.js"));
    fs.copyFileSync(LOCALIZATION_SOURCE_FILE, path.join(distDir, "uiLocalization.js"));
    if (fs.existsSync(LOCALES_JSON_FILE)) {
        fs.copyFileSync(LOCALES_JSON_FILE, path.join(distDir, "locales.json"));
    }

    const results = [
        { file: "dist/gatewayForwarder.js", status: "installed" },
        { file: "dist/networkAndPlugins.js", status: "installed" },
        { file: "dist/uiLocalization.js", status: "installed" },
        { file: "dist/locales.json", status: "installed" },
        patchDebugConsoleJs(distDir),
        patchMainJs(distDir, options),
        patchMenuJs(distDir),
        patchUtilsJs(distDir),
        patchWslJs(distDir),
        patchLanguageServerJs(distDir)
    ];

    return results;
}

module.exports = {
    applyAllJsPatches
};
