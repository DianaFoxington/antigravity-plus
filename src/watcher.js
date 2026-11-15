"use strict";

/**
 * Auto Re-Patch Watcher & Persistent OS Registration (Windows / macOS / Linux).
 *
 * Detects whenever Antigravity is updated (new `app.asar` or replaced `language_server` binary)
 * and re-applies all Electron + Binary patches automatically in ~2 seconds while keeping
 * `~/.gemini/antigravity.json` and OAuth profiles 100% intact.
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const { execFileSync } = require("child_process");
const {
    PERSISTENT_HOME_DIR,
    PERSISTENT_STATE_FILE,
    getInstallLayout,
    isAntigravityRunning,
    launchAntigravityDetached
} = require("./paths");
const { getPatchStatus, patchAntigravity } = require("./patcher");

const WIN_TASK_NAME = "AntigravityAutoPatcher";
const MAC_PLIST_LABEL = "com.antigravity.unlocker.watcher";
const LINUX_UNIT_NAME = "antigravity-unlocker";

function appendWatcherLog(message) {
    try {
        fs.mkdirSync(PERSISTENT_HOME_DIR, { recursive: true });
        const logFile = path.join(PERSISTENT_HOME_DIR, "watcher.log");
        const line = `[${new Date().toISOString()}] ${message}\n`;
        fs.appendFileSync(logFile, line, "utf8");
    } catch {}
}

/**
 * Copies the self-contained patcher scripts into `~/.gemini/agy-unlocker/runtime/`
 * so auto-repatching continues working even if the user deletes the cloned Git repo.
 */
function syncRuntimeToPersistentHome(repoRootDir) {
    const runtimeDir = path.join(PERSISTENT_HOME_DIR, "runtime");
    const runtimeSrcDir = path.join(runtimeDir, "src");
    fs.mkdirSync(runtimeSrcDir, { recursive: true });

    const rootFiles = ["cli.js", "package.json"];
    for (const f of rootFiles) {
        const src = path.join(repoRootDir, f);
        const dst = path.join(runtimeDir, f);
        if (fs.existsSync(src) && path.resolve(src) !== path.resolve(dst)) {
            fs.copyFileSync(src, dst);
        }
    }

    const srcFolder = path.join(repoRootDir, "src");
    if (fs.existsSync(srcFolder)) {
        for (const f of fs.readdirSync(srcFolder)) {
            if (!f.endsWith(".js") && !f.endsWith(".json")) continue;
            const src = path.join(srcFolder, f);
            const dst = path.join(runtimeSrcDir, f);
            if (path.resolve(src) !== path.resolve(dst)) {
                fs.copyFileSync(src, dst);
            }
        }
    }

    return path.join(runtimeDir, "cli.js");
}

/**
 * Fast (<15ms) single-shot check invoked by scheduled task / launchd / systemd / wrapper launcher.
 */
function checkAndRepatchIfUpdated(options = {}) {
    const { customPath = null, forceEvenIfRunning = false } = options;
    let layout;
    try {
        layout = getInstallLayout(customPath);
    } catch {
        return { action: "no_install_found" };
    }

    // Fast path: check saved stat fingerprint before reading 187MB binary!
    const hasLiveAsar = fs.existsSync(layout.asarPath);
    const hasGatewayJs = fs.existsSync(path.join(layout.appDir, "dist", "gatewayForwarder.js"));

    if (!hasLiveAsar && hasGatewayJs && fs.existsSync(PERSISTENT_STATE_FILE) && fs.existsSync(layout.lsBinaryPath)) {
        try {
            const saved = JSON.parse(fs.readFileSync(PERSISTENT_STATE_FILE, "utf8"));
            const st = fs.statSync(layout.lsBinaryPath);
            if (
                saved.lsStat &&
                saved.lsStat.size === st.size &&
                saved.lsStat.mtimeMs === Math.floor(st.mtimeMs)
            ) {
                return { action: "already_up_to_date", fastPath: true };
            }
        } catch {}
    }

    // Deeper inspection if fingerprint changed or `app.asar` reappeared
    const status = getPatchStatus(customPath);
    if (!status.needsRepatch) {
        return { action: "already_up_to_date", fastPath: false };
    }

    // If Antigravity is currently running and forceEvenIfRunning is false, wait until user closes it
    // unless `app.asar` just appeared while app is closed.
    if (status.running && !forceEvenIfRunning) {
        appendWatcherLog("Detected unpatched update while Antigravity is running; will auto-patch as soon as process exits.");
        return { action: "deferred_app_running" };
    }

    appendWatcherLog(`Detected Antigravity update at ${layout.resourcesDir} — applying patches automatically...`);
    const res = patchAntigravity({
        customPath: layout.resourcesDir,
        autoRestartApp: status.running && forceEvenIfRunning
    });
    appendWatcherLog(`Auto-repatch succeeded for Antigravity v${res.appVersion} (freshAsar=${res.extractedFreshAsar}, bin=${res.binResult.status}).`);
    return { action: "repatched", result: res };
}

function createSmartLaunchers(layout, runtimeCliPath) {
    const nodeBin = process.execPath;
    fs.mkdirSync(PERSISTENT_HOME_DIR, { recursive: true });

    if (process.platform === "win32") {
        // 1. Silent VBS runner for background scheduled task (0 = hidden window, zero console flash!)
        const silentVbsPath = path.join(PERSISTENT_HOME_DIR, "silent-check.vbs");
        const escapedNode = nodeBin.replace(/"/g, '""');
        const escapedCli = runtimeCliPath.replace(/"/g, '""');
        const vbsContent = [
            'Set WshShell = CreateObject("WScript.Shell")',
            `WshShell.Run """${escapedNode}"" ""${escapedCli}"" check-once", 0, False`
        ].join("\r\n");
        fs.writeFileSync(silentVbsPath, vbsContent, "utf8");

        // 2. Smart instant launcher (checks & heals before launching Antigravity.exe)
        const smartLauncherCmd = path.join(PERSISTENT_HOME_DIR, "agy-launch.cmd");
        const cmdContent = [
            "@echo off",
            `"${nodeBin}" "${runtimeCliPath}" check-once --force`,
            layout.appExecutable ? `start "" "${layout.appExecutable}" %*` : ""
        ].filter(Boolean).join("\r\n");
        fs.writeFileSync(smartLauncherCmd, cmdContent, "utf8");

        return { silentVbsPath, smartLauncherPath: smartLauncherCmd };
    }

    const smartLauncherSh = path.join(PERSISTENT_HOME_DIR, "agy-launch.sh");
    const shContent = [
        "#!/usr/bin/env bash",
        `"${nodeBin}" "${runtimeCliPath}" check-once --force >/dev/null 2>&1 || true`,
        layout.appExecutable ? `exec "${layout.appExecutable}" "$@"` : ""
    ].filter(Boolean).join("\n");
    fs.writeFileSync(smartLauncherSh, shContent, { encoding: "utf8", mode: 0o755 });
    return { smartLauncherPath: smartLauncherSh };
}

function installPersistentWatcher(repoRootDir, customPath = null) {
    const layout = getInstallLayout(customPath);
    const runtimeCliPath = syncRuntimeToPersistentHome(repoRootDir);
    const launchers = createSmartLaunchers(layout, runtimeCliPath);
    const nodeBin = process.execPath;

    if (process.platform === "win32") {
        const trCmd = `wscript.exe "${launchers.silentVbsPath}"`;
        execFileSync("schtasks", [
            "/Create",
            "/SC", "MINUTE",
            "/MO", "1",
            "/TN", WIN_TASK_NAME,
            "/TR", trCmd,
            "/F"
        ], { stdio: "ignore" });
        appendWatcherLog(`Registered Windows Scheduled Task '${WIN_TASK_NAME}'.`);
        return {
            installed: true,
            mechanism: "Windows Task Scheduler (silent background check every 60s + smart launcher)",
            taskName: WIN_TASK_NAME,
            smartLauncher: launchers.smartLauncherPath
        };
    }

    if (process.platform === "darwin") {
        const agentsDir = path.join(os.homedir(), "Library", "LaunchAgents");
        fs.mkdirSync(agentsDir, { recursive: true });
        const plistPath = path.join(agentsDir, `${MAC_PLIST_LABEL}.plist`);
        const plistXml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${MAC_PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${nodeBin}</string>
        <string>${runtimeCliPath}</string>
        <string>check-once</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>WatchPaths</key>
    <array>
        <string>${layout.resourcesDir}</string>
        <string>${layout.binDir}</string>
    </array>
</dict>
</plist>
`;
        fs.writeFileSync(plistPath, plistXml, "utf8");
        try { execFileSync("launchctl", ["unload", plistPath], { stdio: "ignore" }); } catch {}
        execFileSync("launchctl", ["load", "-w", plistPath], { stdio: "ignore" });
        appendWatcherLog(`Registered macOS LaunchAgent '${plistPath}'.`);
        return {
            installed: true,
            mechanism: "macOS LaunchAgent WatchPaths (instant zero-CPU event trigger)",
            plistPath,
            smartLauncher: launchers.smartLauncherPath
        };
    }

    // Linux: systemd --user path unit
    const systemdUserDir = path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config"), "systemd", "user");
    fs.mkdirSync(systemdUserDir, { recursive: true });
    const servicePath = path.join(systemdUserDir, `${LINUX_UNIT_NAME}.service`);
    const pathUnitPath = path.join(systemdUserDir, `${LINUX_UNIT_NAME}.path`);

    fs.writeFileSync(servicePath, [
        "[Unit]",
        "Description=Antigravity Auto Re-Patcher",
        "",
        "[Service]",
        "Type=oneshot",
        `ExecStart="${nodeBin}" "${runtimeCliPath}" check-once`
    ].join("\n") + "\n", "utf8");

    fs.writeFileSync(pathUnitPath, [
        "[Unit]",
        "Description=Watch Antigravity resources for updates",
        "",
        "[Path]",
        `PathChanged=${layout.resourcesDir}`,
        `PathChanged=${layout.binDir}`,
        "",
        "[Install]",
        "WantedBy=default.target"
    ].join("\n") + "\n", "utf8");

    try {
        execFileSync("systemctl", ["--user", "daemon-reload"], { stdio: "ignore" });
        execFileSync("systemctl", ["--user", "enable", "--now", `${LINUX_UNIT_NAME}.path`], { stdio: "ignore" });
    } catch {}

    appendWatcherLog(`Registered Linux systemd user path unit '${pathUnitPath}'.`);
    return {
        installed: true,
        mechanism: "Linux systemd --user PathChanged unit + smart launcher",
        pathUnitPath,
        smartLauncher: launchers.smartLauncherPath
    };
}

function uninstallPersistentWatcher() {
    if (process.platform === "win32") {
        try {
            execFileSync("schtasks", ["/Delete", "/TN", WIN_TASK_NAME, "/F"], { stdio: "ignore" });
        } catch {}
        return { removed: true, mechanism: "Windows Task Scheduler", taskName: WIN_TASK_NAME };
    }
    if (process.platform === "darwin") {
        const plistPath = path.join(os.homedir(), "Library", "LaunchAgents", `${MAC_PLIST_LABEL}.plist`);
        try { execFileSync("launchctl", ["unload", plistPath], { stdio: "ignore" }); } catch {}
        try { if (fs.existsSync(plistPath)) fs.unlinkSync(plistPath); } catch {}
        return { removed: true, mechanism: "macOS LaunchAgent", plistPath };
    }
    const systemdUserDir = path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config"), "systemd", "user");
    try { execFileSync("systemctl", ["--user", "disable", "--now", `${LINUX_UNIT_NAME}.path`], { stdio: "ignore" }); } catch {}
    for (const ext of ["path", "service"]) {
        const p = path.join(systemdUserDir, `${LINUX_UNIT_NAME}.${ext}`);
        try { if (fs.existsSync(p)) fs.unlinkSync(p); } catch {}
    }
    try { execFileSync("systemctl", ["--user", "daemon-reload"], { stdio: "ignore" }); } catch {}
    return { removed: true, mechanism: "Linux systemd --user unit" };
}

function isWatcherInstalled() {
    if (process.platform === "win32") {
        try {
            execFileSync("schtasks", ["/Query", "/TN", WIN_TASK_NAME], { stdio: "ignore" });
            return true;
        } catch {
            return false;
        }
    }
    if (process.platform === "darwin") {
        return fs.existsSync(path.join(os.homedir(), "Library", "LaunchAgents", `${MAC_PLIST_LABEL}.plist`));
    }
    const systemdUserDir = path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config"), "systemd", "user");
    return fs.existsSync(path.join(systemdUserDir, `${LINUX_UNIT_NAME}.path`));
}

/**
 * Optional foreground continuous watcher (`node cli.js watch`).
 */
function runForegroundWatchLoop(customPath = null, intervalMs = 15000) {
    console.log(`[Watcher] Monitoring Antigravity installation every ${intervalMs / 1000}s... (Press Ctrl+C to stop)`);
    const tick = () => {
        try {
            const res = checkAndRepatchIfUpdated({ customPath, forceEvenIfRunning: false });
            if (res.action === "repatched") {
                console.log(`[Watcher] Auto-repatched Antigravity v${res.result.appVersion} at ${new Date().toLocaleTimeString()}`);
            }
        } catch (err) {
            console.error("[Watcher] Error:", err.message);
        }
    };
    tick();
    setInterval(tick, intervalMs);
}

module.exports = {
    syncRuntimeToPersistentHome,
    checkAndRepatchIfUpdated,
    installPersistentWatcher,
    uninstallPersistentWatcher,
    isWatcherInstalled,
    runForegroundWatchLoop
};
