"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const { execFileSync, spawn } = require("child_process");

const PERSISTENT_HOME_DIR = path.join(os.homedir(), ".gemini", "agy-unlocker");
const PERSISTENT_STATE_FILE = path.join(PERSISTENT_HOME_DIR, "patch-state.json");

function normalizeResourcesCandidate(inputPath) {
    if (!inputPath) return null;
    const p = path.resolve(inputPath);
    if (!fs.existsSync(p)) return null;

    // Direct resources folder
    if (
        fs.existsSync(path.join(p, "app.asar")) ||
        fs.existsSync(path.join(p, "app.asar.bak")) ||
        fs.existsSync(path.join(p, "app", "package.json"))
    ) {
        return p;
    }

    // macOS .app bundle root
    const macRes = path.join(p, "Contents", "Resources");
    if (fs.existsSync(macRes) && normalizeResourcesCandidate(macRes)) {
        return macRes;
    }

    // Windows / Linux install root containing resources/
    const subRes = path.join(p, "resources");
    if (fs.existsSync(subRes) && normalizeResourcesCandidate(subRes)) {
        return subRes;
    }

    // Executable path passed directly
    if (fs.statSync(p).isFile()) {
        const parent = path.dirname(p);
        const fromExeWin = path.join(parent, "resources");
        if (fs.existsSync(fromExeWin) && normalizeResourcesCandidate(fromExeWin)) return fromExeWin;
        const fromExeMac = path.resolve(parent, "..", "Resources");
        if (fs.existsSync(fromExeMac) && normalizeResourcesCandidate(fromExeMac)) return fromExeMac;
    }

    return null;
}

function discoverWindowsDynamicCandidates(home, localAppData) {
    const found = [];
    const pushIf = p => { if (p && typeof p === "string") found.push(p.trim().replace(/^"|"$/g, "")); };

    // 1. Standard directories + wildcard scan in Programs / Users
    const progFiles = process.env.PROGRAMFILES || "C:\\Program Files";
    const progFilesX86 = process.env["PROGRAMFILES(X86)"] || "C:\\Program Files (x86)";
    pushIf(path.join(localAppData, "Programs", "antigravity", "resources"));
    pushIf(path.join(localAppData, "Programs", "Antigravity", "resources"));
    pushIf(path.join(localAppData, "antigravity", "resources"));
    pushIf(path.join(localAppData, "Antigravity", "resources"));
    pushIf(path.join(progFiles, "Antigravity", "resources"));
    pushIf(path.join(progFilesX86, "Antigravity", "resources"));

    // Check C:\Users\*\AppData\Local\Programs\antigravity (handles elevated/admin2 accounts)
    try {
        const usersRoot = path.dirname(home);
        if (fs.existsSync(usersRoot)) {
            for (const u of fs.readdirSync(usersRoot)) {
                pushIf(path.join(usersRoot, u, "AppData", "Local", "Programs", "antigravity", "resources"));
                pushIf(path.join(usersRoot, u, "AppData", "Local", "Programs", "Antigravity", "resources"));
            }
        }
    } catch {}

    // Check common drive roots (portable / custom drive installs)
    for (const drv of ["C:\\", "D:\\", "E:\\", "F:\\"]) {
        pushIf(path.join(drv, "Antigravity", "resources"));
        pushIf(path.join(drv, "antigravity", "resources"));
        pushIf(path.join(drv, "Programs", "Antigravity", "resources"));
        pushIf(path.join(drv, "Programs", "antigravity", "resources"));
        pushIf(path.join(drv, "Apps", "Antigravity", "resources"));
    }

    // 2. Running process, Registry Uninstall keys, and Start Menu / Desktop shortcuts
    try {
        const psScript = [
            "$ErrorActionPreference='SilentlyContinue'",
            "Get-Process -Name '*Antigravity*' | ForEach-Object { if ($_.Path) { $_.Path } }",
            "$regRoots = @('HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*')",
            "Get-ItemProperty $regRoots | Where-Object { $_.DisplayName -match 'Antigravity' -or $_.UninstallString -match 'Antigravity' } | ForEach-Object { $_.InstallLocation; ($_.DisplayIcon -split ',')[0]; ($_.UninstallString -replace '\"','' -split ' /')[0] }",
            "$ws = New-Object -ComObject WScript.Shell",
            "$lnkDirs = @((Join-Path $env:APPDATA 'Microsoft\\Windows\\Start Menu\\Programs'), (Join-Path $env:USERPROFILE 'Desktop'), (Join-Path $env:PUBLIC 'Desktop'))",
            "foreach ($d in $lnkDirs) { if (Test-Path $d) { Get-ChildItem -LiteralPath $d -Filter '*Antigravity*.lnk' -Recurse | ForEach-Object { $ws.CreateShortcut($_.FullName).TargetPath } } }"
        ].join("; ");
        const out = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", psScript], {
            encoding: "utf8",
            timeout: 5000,
            stdio: ["ignore", "pipe", "ignore"]
        });
        for (const line of String(out || "").split(/\r?\n/)) {
            pushIf(line);
        }
    } catch {}

    return found;
}

function discoverAntigravityResources(customPath = null) {
    if (customPath) {
        const resolved = normalizeResourcesCandidate(customPath);
        if (!resolved) {
            throw new Error(`Could not locate Antigravity resources directory at: ${customPath}`);
        }
        return resolved;
    }

    if (process.env.ANTIGRAVITY_PATH) {
        const envResolved = normalizeResourcesCandidate(process.env.ANTIGRAVITY_PATH);
        if (envResolved) return envResolved;
    }

    // Check saved state path first if still valid
    try {
        if (fs.existsSync(PERSISTENT_STATE_FILE)) {
            const st = JSON.parse(fs.readFileSync(PERSISTENT_STATE_FILE, "utf8"));
            const saved = normalizeResourcesCandidate(st.resourcesDir);
            if (saved) return saved;
        }
    } catch {}

    const home = os.homedir();
    const candidates = [];

    if (process.platform === "win32") {
        const localAppData = process.env.LOCALAPPDATA || path.join(home, "AppData", "Local");
        candidates.push(...discoverWindowsDynamicCandidates(home, localAppData));
    } else if (process.platform === "darwin") {
        candidates.push(
            "/Applications/Antigravity.app/Contents/Resources",
            path.join(home, "Applications", "Antigravity.app", "Contents", "Resources")
        );
    } else {
        candidates.push(
            "/opt/Antigravity/resources",
            "/opt/antigravity/resources",
            "/usr/lib/antigravity/resources",
            "/usr/share/antigravity/resources",
            path.join(home, ".local", "share", "antigravity", "resources")
        );
        try {
            const binLoc = execFileSync("which", ["antigravity"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
            if (binLoc) {
                const realBin = fs.realpathSync(binLoc);
                candidates.unshift(path.dirname(realBin), path.resolve(path.dirname(realBin), ".."));
            }
        } catch {}
    }

    for (const c of candidates) {
        const hit = normalizeResourcesCandidate(c);
        if (hit) return hit;
    }

    throw new Error(
        "Could not auto-detect Antigravity installation. Pass --path <Antigravity-Folder> or set ANTIGRAVITY_PATH."
    );
}

function getInstallLayout(customPath = null) {
    const resourcesDir = discoverAntigravityResources(customPath);
    const isWin = process.platform === "win32";
    const isMac = process.platform === "darwin";
    const lsBinName = isWin ? "language_server.exe" : "language_server";

    let appExecutable = null;
    if (isWin) {
        const candidateExe = path.resolve(resourcesDir, "..", "Antigravity.exe");
        if (fs.existsSync(candidateExe)) appExecutable = candidateExe;
    } else if (isMac) {
        const candidateMac = path.resolve(resourcesDir, "..", "MacOS", "Antigravity");
        if (fs.existsSync(candidateMac)) appExecutable = candidateMac;
    } else {
        for (const nm of ["antigravity", "Antigravity"]) {
            const c = path.resolve(resourcesDir, "..", nm);
            if (fs.existsSync(c)) {
                appExecutable = c;
                break;
            }
        }
    }

    return {
        resourcesDir,
        installRoot: isMac ? path.resolve(resourcesDir, "..", "..") : path.resolve(resourcesDir, ".."),
        appDir: path.join(resourcesDir, "app"),
        asarPath: path.join(resourcesDir, "app.asar"),
        asarBakPath: path.join(resourcesDir, "app.asar.bak"),
        asarUnpackedDir: path.join(resourcesDir, "app.asar.unpacked"),
        binDir: path.join(resourcesDir, "bin"),
        lsBinaryPath: path.join(resourcesDir, "bin", lsBinName),
        lsBakPath: path.join(resourcesDir, "bin", `${lsBinName}.bak`),
        appExecutable,
        persistentHomeDir: PERSISTENT_HOME_DIR,
        persistentStateFile: PERSISTENT_STATE_FILE
    };
}

function readAppVersion(layout) {
    try {
        const pkgPath = path.join(layout.appDir, "package.json");
        if (fs.existsSync(pkgPath)) {
            return JSON.parse(fs.readFileSync(pkgPath, "utf8")).version || "unknown";
        }
    } catch {}
    return "unknown";
}

function isAntigravityRunning() {
    try {
        if (process.platform === "win32") {
            const out = execFileSync("tasklist", ["/FI", "IMAGENAME eq Antigravity.exe", "/NH"], {
                encoding: "utf8",
                stdio: ["ignore", "pipe", "ignore"]
            });
            if (/Antigravity\.exe/i.test(out)) return true;
            const outLs = execFileSync("tasklist", ["/FI", "IMAGENAME eq language_server.exe", "/NH"], {
                encoding: "utf8",
                stdio: ["ignore", "pipe", "ignore"]
            });
            return /language_server\.exe/i.test(outLs);
        }
        const out = execFileSync("pgrep", ["-f", "Antigravity|language_server"], {
            encoding: "utf8",
            stdio: ["ignore", "pipe", "ignore"]
        });
        return Boolean(out.trim());
    } catch {
        return false;
    }
}

function stopRunningAntigravity() {
    if (process.platform === "win32") {
        for (const img of ["Antigravity.exe", "language_server.exe"]) {
            try {
                execFileSync("taskkill", ["/F", "/IM", img, "/T"], { stdio: "ignore" });
            } catch {}
        }
    } else {
        for (const pat of ["Antigravity", "language_server"]) {
            try {
                execFileSync("pkill", ["-f", pat], { stdio: "ignore" });
            } catch {}
        }
    }
}

function launchAntigravityDetached(layout) {
    if (!layout.appExecutable || !fs.existsSync(layout.appExecutable)) return false;
    if (process.platform === "win32") {
        try {
            execFileSync("powershell.exe", [
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                `Start-Process -FilePath '${layout.appExecutable.replace(/'/g, "''")}'`
            ], { stdio: "ignore" });
            return true;
        } catch {}
    }
    const child = spawn(layout.appExecutable, [], {
        detached: true,
        stdio: "ignore"
    });
    child.unref();
    return true;
}

module.exports = {
    PERSISTENT_HOME_DIR,
    PERSISTENT_STATE_FILE,
    discoverAntigravityResources,
    getInstallLayout,
    readAppVersion,
    isAntigravityRunning,
    stopRunningAntigravity,
    launchAntigravityDetached
};
