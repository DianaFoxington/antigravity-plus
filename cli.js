#!/usr/bin/env node
"use strict";

const path = require("path");
const { getPatchStatus, patchAntigravity, unpatchAntigravity } = require("./src/patcher");
const {
    checkAndRepatchIfUpdated,
    installPersistentWatcher,
    uninstallPersistentWatcher,
    isWatcherInstalled,
    runForegroundWatchLoop
} = require("./src/watcher");

function parseCliArgs(argv) {
    const args = argv.slice(2);
    const command = (args.find(a => !a.startsWith("-")) || "help").toLowerCase();
    let customPath = null;
    let keepAutoUpdater = false;
    let noRestart = false;
    let force = false;
    let withWatcher = true;

    for (let i = 0; i < args.length; i++) {
        const a = args[i];
        if (a === "--path" || a === "-p") {
            customPath = args[++i] || null;
        } else if (a.startsWith("--path=")) {
            customPath = a.slice("--path=".length);
        } else if (a === "--keep-updater") {
            keepAutoUpdater = true;
        } else if (a === "--no-restart") {
            noRestart = true;
        } else if (a === "--no-watcher") {
            withWatcher = false;
        } else if (a === "--force" || a === "-f") {
            force = true;
        }
    }

    return { command, customPath, keepAutoUpdater, noRestart, force, withWatcher };
}

function printBanner() {
    console.log("============================================================");
    console.log("  Antigravity Plus — Multi-Provider Gateway & Full Unlocker");
    console.log("  Cross-Platform Patcher (Windows · macOS · Linux)");
    console.log("============================================================");
}

function main() {
    const opts = parseCliArgs(process.argv);

    try {
        if (opts.command === "check-once") {
            const res = checkAndRepatchIfUpdated({
                customPath: opts.customPath,
                forceEvenIfRunning: opts.force
            });
            if (res.action === "repatched") {
                console.log(`[AutoPatcher] Re-patched Antigravity v${res.result.appVersion}`);
            }
            return;
        }

        printBanner();

        if (opts.command === "patch" || opts.command === "install") {
            console.log("\n[1/2] Applying Electron + Language Server dynamic patches...");
            const res = patchAntigravity({
                customPath: opts.customPath,
                keepAutoUpdater: opts.keepAutoUpdater,
                autoRestartApp: !opts.noRestart
            });

            console.log(`  -> Target:      ${res.resourcesDir}`);
            console.log(`  -> Version:     v${res.appVersion}`);
            console.log(`  -> Fresh ASAR:  ${res.extractedFreshAsar ? "Extracted & backed up" : "Using unpacked app/"}`);
            for (const jr of res.jsResults) {
                console.log(`  -> JS Patch:    ${jr.file} [${jr.status}]`);
            }
            console.log(`  -> LS Binary:   ${res.binResult.status} (arch=${res.binResult.arch || "unknown"})`);
            for (const br of (res.binResult.appliedRules || [])) {
                console.log(`     * ${br.id}: ${br.status}${br.offsets ? ` @ ${br.offsets.join(", ")}` : ""}`);
            }

            if (opts.withWatcher) {
                console.log("\n[2/2] Registering Auto Re-Patch Watcher (survives future app updates)...");
                const wRes = installPersistentWatcher(__dirname, opts.customPath);
                console.log(`  -> Mechanism:   ${wRes.mechanism}`);
                console.log(`  -> Launcher:    ${wRes.smartLauncher}`);
            }

            console.log("\nDone! Your ~/.gemini/antigravity.json keys & OAuth profiles were kept untouched.");
            return;
        }

        if (opts.command === "unpatch" || opts.command === "uninstall" || opts.command === "restore") {
            console.log("\n[1/2] Removing background Auto Re-Patch Watcher...");
            const wRem = uninstallPersistentWatcher();
            console.log(`  -> Removed:     ${wRem.mechanism}`);

            console.log("\n[2/2] Restoring original Antigravity files from backup...");
            const res = unpatchAntigravity({
                customPath: opts.customPath,
                autoRestartApp: !opts.noRestart
            });
            console.log(`  -> Target:      ${res.resourcesDir}`);
            console.log(`  -> app.asar:    ${res.restoredAsar ? "Restored from app.asar.bak" : "Already stock"}`);
            console.log(`  -> LS Binary:   ${res.restoredBinary ? "Restored from .bak" : "Already stock"}`);
            console.log(`  -> User Data:   ${res.note}`);
            console.log("\nOriginal Antigravity installation restored cleanly.");
            return;
        }

        if (opts.command === "status") {
            const st = getPatchStatus(opts.customPath);
            const watcherActive = isWatcherInstalled();
            console.log(`\n  Install Path:     ${st.layout.resourcesDir}`);
            console.log(`  App Version:      v${st.appVersion}`);
            console.log(`  App Running:      ${st.running ? "Yes" : "No"}`);
            console.log(`  Overall Status:   ${st.fullyPatched ? "FULLY PATCHED" : (st.needsRepatch ? "NEEDS PATCH / UPDATE DETECTED" : "PARTIAL")}`);
            console.log(`  Auto-Watcher:     ${watcherActive ? "ACTIVE (auto-heals after updates)" : "Not installed"}`);
            console.log(`  Gateway JS:       ${st.electron.hasGatewayJs ? "Installed" : "Missing"}`);
            console.log(`  ASAR Backup:      ${st.electron.hasAsarBak ? "Present (app.asar.bak)" : "None"}`);
            console.log(`  LS Binary (${st.languageServer.arch}): ${st.languageServer.isPatched ? "Patched" : "Unpatched"}`);
            for (const d of (st.languageServer.details || [])) {
                console.log(`    - ${d.id}: patched=${JSON.stringify(d.patchedMatches)} unpatched=${JSON.stringify(d.unpatchedMatches)}`);
            }
            return;
        }

        if (opts.command === "install-watcher") {
            const wRes = installPersistentWatcher(__dirname, opts.customPath);
            console.log(`\n  Auto-Watcher installed: ${wRes.mechanism}`);
            console.log(`  Smart Launcher:         ${wRes.smartLauncher}`);
            return;
        }

        if (opts.command === "uninstall-watcher") {
            const wRem = uninstallPersistentWatcher();
            console.log(`\n  Auto-Watcher removed: ${wRem.mechanism}`);
            return;
        }

        if (opts.command === "watch") {
            runForegroundWatchLoop(opts.customPath);
            return;
        }

        console.log(`
Usage:
  node cli.js patch [options]             Apply all patches + install auto-update watcher
  node cli.js unpatch [options]           Restore stock Antigravity from backups
  node cli.js status [options]            Show current patch & binary signature status
  node cli.js install-watcher [options]   Register silent OS auto-repatch watcher
  node cli.js uninstall-watcher           Remove background OS auto-repatch watcher
  node cli.js watch [options]             Run foreground file watcher loop

Options:
  --path, -p <dir>     Explicit path to Antigravity install or resources directory
  --no-watcher         Skip registering background auto-repatch watcher during patch
  --no-restart         Do not automatically relaunch Antigravity if it was open
  --keep-updater       Keep Electron background auto-updater enabled
`);
    } catch (err) {
        console.error(`\n[ERROR] ${err.message}`);
        process.exit(1);
    }
}

main();
