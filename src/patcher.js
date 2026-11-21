"use strict";

const fs = require("fs");
const path = require("path");
const {
    getInstallLayout,
    readAppVersion,
    isAntigravityRunning,
    stopRunningAntigravity,
    launchAntigravityDetached
} = require("./paths");
const { extractAsarArchive, removeDirRecursive } = require("./asar");
const { applyAllJsPatches } = require("./jsPatcher");
const { inspectLanguageServerBinary, patchLanguageServerBinary, safeReplaceFileSync, sleepSync } = require("./binaryPatcher");

function savePatchState(layout, extra = {}) {
    fs.mkdirSync(layout.persistentHomeDir, { recursive: true });
    let lsStat = null;
    try {
        if (fs.existsSync(layout.lsBinaryPath)) {
            const st = fs.statSync(layout.lsBinaryPath);
            lsStat = { size: st.size, mtimeMs: Math.floor(st.mtimeMs) };
        }
    } catch {}

    const state = {
        patchedAt: new Date().toISOString(),
        appVersion: readAppVersion(layout),
        resourcesDir: layout.resourcesDir,
        lsBinaryPath: layout.lsBinaryPath,
        lsStat,
        ...extra
    };
    fs.writeFileSync(layout.persistentStateFile, JSON.stringify(state, null, 2), "utf8");
    return state;
}

function getPatchStatus(customPath = null) {
    const layout = getInstallLayout(customPath);
    const hasLiveAsar = fs.existsSync(layout.asarPath);
    const hasAsarBak = fs.existsSync(layout.asarBakPath);
    const hasUnpackedApp = fs.existsSync(path.join(layout.appDir, "package.json"));
    const hasGatewayJs = fs.existsSync(path.join(layout.appDir, "dist", "gatewayForwarder.js"));
    const lsReport = inspectLanguageServerBinary(layout.lsBinaryPath);

    // Needs patch if:
    // 1. A fresh `app.asar` exists (stock install OR newly updated by installer), OR
    // 2. `gatewayForwarder.js` is missing, OR
    // 3. `language_server` has unpatched byte patterns
    const needsRepatch = hasLiveAsar || !hasUnpackedApp || !hasGatewayJs || Boolean(lsReport.hasUnpatchedTargets);
    const fullyPatched = !hasLiveAsar && hasUnpackedApp && hasGatewayJs && Boolean(lsReport.isPatched);

    return {
        appVersion: readAppVersion(layout),
        running: isAntigravityRunning(),
        fullyPatched,
        needsRepatch,
        layout,
        electron: {
            hasLiveAsar,
            hasAsarBak,
            hasUnpackedApp,
            hasGatewayJs
        },
        languageServer: lsReport
    };
}

function patchAntigravity(options = {}) {
    const {
        customPath = null,
        keepAutoUpdater = false,
        autoRestartApp = true
    } = options;

    const layout = getInstallLayout(customPath);
    const wasRunning = isAntigravityRunning();

    if (wasRunning) {
        stopRunningAntigravity();
        if (process.platform === "win32") sleepSync(400);
    }

    let extractedFreshAsar = false;

    // Case A: Stock install OR post-update install where a new `app.asar` exists!
    // Always extract the new `app.asar` and refresh `app.asar.bak` so updates never run stale JS!
    if (fs.existsSync(layout.asarPath)) {
        extractAsarArchive(layout.asarPath, layout.appDir, layout.asarUnpackedDir);
        if (fs.existsSync(layout.asarBakPath)) {
            fs.unlinkSync(layout.asarBakPath);
        }
        safeReplaceFileSync(layout.asarPath, layout.asarBakPath);
        extractedFreshAsar = true;
    } else if (!fs.existsSync(path.join(layout.appDir, "package.json"))) {
        // Case B: `resources/app` missing, recover from `app.asar.bak`
        if (!fs.existsSync(layout.asarBakPath)) {
            throw new Error(`Neither app.asar nor app.asar.bak found in ${layout.resourcesDir}`);
        }
        extractAsarArchive(layout.asarBakPath, layout.appDir, layout.asarUnpackedDir);
        extractedFreshAsar = true;
    }

    const jsResults = applyAllJsPatches(layout.appDir, { keepAutoUpdater });
    const binResult = patchLanguageServerBinary(layout.lsBinaryPath, layout.lsBakPath);
    const state = savePatchState(layout);

    let relaunched = false;
    if (wasRunning && autoRestartApp) {
        relaunched = launchAntigravityDetached(layout);
    }

    return {
        success: true,
        appVersion: state.appVersion,
        resourcesDir: layout.resourcesDir,
        extractedFreshAsar,
        jsResults,
        binResult,
        wasRunning,
        relaunched
    };
}

function unpatchAntigravity(options = {}) {
    const {
        customPath = null,
        autoRestartApp = false
    } = options;

    const layout = getInstallLayout(customPath);
    const wasRunning = isAntigravityRunning();

    if (wasRunning) {
        stopRunningAntigravity();
        if (process.platform === "win32") sleepSync(400);
    }

    let restoredAsar = false;
    if (fs.existsSync(layout.asarBakPath)) {
        if (fs.existsSync(layout.asarPath)) {
            fs.unlinkSync(layout.asarPath);
        }
        safeReplaceFileSync(layout.asarBakPath, layout.asarPath);
        restoredAsar = true;
    }

    if (fs.existsSync(layout.asarPath) && fs.existsSync(layout.appDir)) {
        removeDirRecursive(layout.appDir);
    }

    let restoredBinary = false;
    if (fs.existsSync(layout.lsBakPath)) {
        if (fs.existsSync(layout.lsBinaryPath)) {
            fs.unlinkSync(layout.lsBinaryPath);
        }
        safeReplaceFileSync(layout.lsBakPath, layout.lsBinaryPath);
        restoredBinary = true;
    }

    try {
        if (fs.existsSync(layout.persistentStateFile)) {
            fs.unlinkSync(layout.persistentStateFile);
        }
    } catch {}

    let relaunched = false;
    if (wasRunning && autoRestartApp) {
        relaunched = launchAntigravityDetached(layout);
    }

    return {
        success: true,
        resourcesDir: layout.resourcesDir,
        restoredAsar,
        restoredBinary,
        note: "User keys and configs in ~/.gemini/ were preserved untouched.",
        relaunched
    };
}

module.exports = {
    getPatchStatus,
    patchAntigravity,
    unpatchAntigravity,
    savePatchState
};
