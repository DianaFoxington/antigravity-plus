"use strict";

/**
 * Dynamic Byte-Pattern Scanner & Binary Patcher for Antigravity's Go `language_server` binary.
 *
 * Zero hardcoded file offsets — scans executable byte patterns dynamically so patches survive
 * future Antigravity releases across Windows (PE x64), macOS (Mach-O arm64 / x64 + ad-hoc codesign),
 * and Linux (ELF x64 / arm64).
 */

const fs = require("fs");
const { execFileSync } = require("child_process");

/**
 * Scan buffer for a pattern array where each byte is either 0x00..0xFF or null (wildcard).
 * Or a predicate function `(b) => boolean`.
 */
function findPatternOffsets(buf, pattern, maxMatches = 8) {
    const matches = [];
    const patLen = pattern.length;
    const limit = buf.length - patLen;
    if (limit < 0) return matches;

    // Fast anchor on the first fixed byte in pattern
    let anchorIdx = -1;
    let anchorVal = 0;
    for (let k = 0; k < patLen; k++) {
        if (typeof pattern[k] === "number") {
            anchorIdx = k;
            anchorVal = pattern[k];
            break;
        }
    }

    let pos = 0;
    while (pos <= limit) {
        if (anchorIdx >= 0) {
            const hit = buf.indexOf(anchorVal, pos + anchorIdx);
            if (hit === -1) break;
            pos = hit - anchorIdx;
            if (pos > limit) break;
        }

        let ok = true;
        for (let j = 0; j < patLen; j++) {
            const rule = pattern[j];
            const byte = buf[pos + j];
            if (typeof rule === "number") {
                if (byte !== rule) {
                    ok = false;
                    break;
                }
            } else if (typeof rule === "function") {
                if (!rule(byte)) {
                    ok = false;
                    break;
                }
            }
        }
        if (ok) {
            matches.push(pos);
            if (matches.length >= maxMatches) break;
            pos += patLen;
        } else {
            pos += 1;
        }
    }
    return matches;
}

const isCmpReg32 = (b) => b >= 0xf8 && b <= 0xff;
const isMovImmReg32 = (b) => b >= 0xb8 && b <= 0xbf;
const isRegModRm = (b) => b >= 0x40 && b <= 0x7f;

// ---------------------------------------------------------------------------
// x86_64 Dynamic Signatures (Windows PE / Linux ELF x64 / macOS Intel)
// ---------------------------------------------------------------------------
const X64_RULES = [
    {
        id: "x64_checkpoint_cap_2m",
        description: "Upgrade GetCheckpointConfig 256K cap (0x3E800) -> 2M (0x200000) for native 1M+ context windows",
        unpatched: [0x81, isCmpReg32, 0x00, 0xe8, 0x03, 0x00, isMovImmReg32, 0x00, 0xe8, 0x03, 0x00, 0x0f, 0x42, null],
        patched:   [0x81, isCmpReg32, 0x00, 0x00, 0x20, 0x00, isMovImmReg32, 0x00, 0x00, 0x20, 0x00, 0x0f, 0x42, null],
        apply(buf, off) {
            // Replace first 0x0003e800 -> 0x00200000 (bytes +2..+5)
            buf[off + 2] = 0x00; buf[off + 3] = 0x00; buf[off + 4] = 0x20; buf[off + 5] = 0x00;
            // Replace second 0x0003e800 -> 0x00200000 (bytes +7..+10)
            buf[off + 7] = 0x00; buf[off + 8] = 0x00; buf[off + 9] = 0x20; buf[off + 10] = 0x00;
        }
    },
    {
        id: "x64_checkpoint_fallback_1m",
        description: "Upgrade GetCheckpointConfig secondary fallback 256K -> 1M (0x100000)",
        unpatched: [0x83, null, 0x14, 0x00, 0x7f, 0x07, 0xc7, 0x40, 0x0c, 0x00, 0xe8, 0x03, 0x00],
        patched:   [0x83, null, 0x14, 0x00, 0x7f, 0x07, 0xc7, 0x40, 0x0c, 0x00, 0x00, 0x10, 0x00],
        apply(buf, off) {
            buf[off + 9] = 0x00; buf[off + 10] = 0x00; buf[off + 11] = 0x10; buf[off + 12] = 0x00;
        }
    },
    {
        id: "x64_mendel_devmode_unlock",
        description: "Unlock SetMendelFlagOverrides in packaged production builds (bypass devMode gate)",
        unpatched: [0x48, 0x8b, isRegModRm, 0x08, 0x48, 0x85, null, 0x74, 0x06, 0x80, isRegModRm, 0x01, 0x00, 0x75, null],
        patched:   [0x48, 0x8b, isRegModRm, 0x08, 0x48, 0x85, null, 0x90, 0x90, 0x80, isRegModRm, 0x01, 0x00, 0xeb, null],
        apply(buf, off) {
            // NOP out `jz +6` (74 06 -> 90 90) and make `jnz` unconditional `jmp` (75 -> eb)
            buf[off + 7] = 0x90;
            buf[off + 8] = 0x90;
            buf[off + 13] = 0xeb;
        }
    }
];

// ---------------------------------------------------------------------------
// ARM64 Dynamic Signatures (macOS Apple Silicon & Linux aarch64)
// In ARM64 Go binaries, 256,000 (0x3E800) is materialized via:
//   MOVZ Wd, #0xE800         -> [Rd, 0x00, 0x9d, 0x52] (little-endian: (0x529d0000 | Rd))
//   MOVK Wd, #0x3, LSL #16   -> [0x60|Rd, 0x00, 0xa0, 0x72] (little-endian: (0x72a00060 | Rd))
// Upgraded to 2M (0x200000):
//   MOVZ Wd, #0x20, LSL #16  -> (0x52a00400 | Rd)
//   NOP                      -> 0xd503201f
// ---------------------------------------------------------------------------
function scanAndPatchArm64CheckpointCap(buf, dryRun = false) {
    let patchedHits = 0;
    let alreadyPatchedHits = 0;
    const limit = buf.length - 16;

    for (let off = 0; off <= limit; off += 4) {
        // Fast check for 0x52 in byte +3 (MOVZ 32-bit)
        if (buf[off + 3] !== 0x52) continue;
        const insn1 = buf.readUInt32LE(off);
        const insn2 = buf.readUInt32LE(off + 4);
        const insn3 = buf.readUInt32LE(off + 8);
        const insn4 = buf.readUInt32LE(off + 12);

        const rd = insn1 & 0x1f;
        // Check MOVZ Wd, #0xe800 (0x529d0000 | rd) + MOVK Wd, #0x3, LSL #16 (0x72a00060 | rd)
        if ((insn1 >>> 5) === (0x529d0000 >>> 5) && insn2 === ((0x72a00060 | rd) >>> 0)) {
            // Confirm adjacent CMP / CSEL within next 2 instructions so we only hit min-clamp logic
            const isClamp = ((insn3 & 0x7f000000) === 0x6b000000) || ((insn4 & 0x7fe00000) === 0x1a800000);
            if (isClamp) {
                if (!dryRun) {
                    buf.writeUInt32LE((0x52a00400 | rd) >>> 0, off);     // MOVZ Wd, #0x20, LSL #16 (2,097,152)
                    buf.writeUInt32LE(0xd503201f, off + 4);              // NOP
                }
                patchedHits++;
            }
        } else if ((insn1 >>> 5) === (0x52a00400 >>> 5) && insn2 === 0xd503201f) {
            const isClamp = ((insn3 & 0x7f000000) === 0x6b000000) || ((insn4 & 0x7fe00000) === 0x1a800000);
            if (isClamp) alreadyPatchedHits++;
        }
    }
    return { patchedHits, alreadyPatchedHits };
}

function detectBinaryArch(buf) {
    if (buf.length < 20) return "unknown";
    // PE (MZ)
    if (buf[0] === 0x4d && buf[1] === 0x5a) {
        const peOff = buf.readUInt32LE(0x3c);
        if (peOff + 6 < buf.length) {
            const machine = buf.readUInt16LE(peOff + 4);
            if (machine === 0x8664) return "x64";
            if (machine === 0xaa64) return "arm64";
        }
        return "x64";
    }
    // ELF (\x7FELF)
    if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
        const eMachine = buf.readUInt16LE(0x12);
        if (eMachine === 0x3e) return "x64";
        if (eMachine === 0xb7) return "arm64";
    }
    // Mach-O 64-bit (0xfeedfacf) or Universal Fat binary (0xcafebabe)
    const magic = buf.readUInt32LE(0);
    if (magic === 0xfeedfacf) {
        const cpuType = buf.readUInt32LE(4);
        if (cpuType === 0x01000007) return "x64";
        if (cpuType === 0x0100000c) return "arm64";
    }
    if (magic === 0xbebafeca || magic === 0xcafebabe) {
        return "universal";
    }
    return process.arch === "arm64" ? "arm64" : "x64";
}

function sleepSync(ms) {
    try {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
    } catch {
        const end = Date.now() + ms;
        while (Date.now() < end) {}
    }
}

function safeReplaceFileSync(srcPath, destPath) {
    let lastErr = null;
    for (let attempt = 0; attempt < 8; attempt++) {
        try {
            fs.renameSync(srcPath, destPath);
            return;
        } catch (err) {
            lastErr = err;
            if (err && (err.code === "EPERM" || err.code === "EBUSY" || err.code === "EACCES")) {
                sleepSync(150 * (attempt + 1));
                continue;
            }
            throw err;
        }
    }
    // Final fallback on Windows when AV briefly holds rename lock on .patching file
    try {
        fs.copyFileSync(srcPath, destPath);
        try { fs.unlinkSync(srcPath); } catch {}
        return;
    } catch {
        throw lastErr;
    }
}

function resignMacOsBinaryIfNeeded(binaryPath) {
    if (process.platform !== "darwin") return false;
    try {
        execFileSync("codesign", ["--force", "--sign", "-", binaryPath], { stdio: "ignore" });
        return true;
    } catch {
        return false;
    }
}

function inspectLanguageServerBinary(lsBinaryPath) {
    if (!fs.existsSync(lsBinaryPath)) {
        return { exists: false, arch: "missing", isPatched: false, details: [] };
    }
    const buf = fs.readFileSync(lsBinaryPath);
    const arch = detectBinaryArch(buf);
    const details = [];
    let anyPatched = false;
    let anyUnpatched = false;

    if (arch === "x64" || arch === "universal") {
        for (const rule of X64_RULES) {
            const pOffs = findPatternOffsets(buf, rule.patched, 4);
            const uOffs = findPatternOffsets(buf, rule.unpatched, 4);
            if (pOffs.length > 0) anyPatched = true;
            if (uOffs.length > 0) anyUnpatched = true;
            details.push({
                id: rule.id,
                patchedMatches: pOffs.map(o => `0x${o.toString(16)}`),
                unpatchedMatches: uOffs.map(o => `0x${o.toString(16)}`)
            });
        }
    }

    if (arch === "arm64" || arch === "universal") {
        const armRes = scanAndPatchArm64CheckpointCap(buf, true);
        if (armRes.alreadyPatchedHits > 0) anyPatched = true;
        if (armRes.patchedHits > 0) anyUnpatched = true;
        details.push({
            id: "arm64_checkpoint_cap_2m",
            patchedMatches: armRes.alreadyPatchedHits,
            unpatchedMatches: armRes.patchedHits
        });
    }

    return {
        exists: true,
        arch,
        size: buf.length,
        isPatched: anyPatched && !anyUnpatched,
        partiallyPatched: anyPatched && anyUnpatched,
        hasUnpatchedTargets: anyUnpatched,
        details
    };
}

function patchLanguageServerBinary(lsBinaryPath, lsBakPath) {
    if (!fs.existsSync(lsBinaryPath)) {
        return { status: "skipped_missing", appliedRules: [] };
    }

    const buf = fs.readFileSync(lsBinaryPath);
    const arch = detectBinaryArch(buf);
    const appliedRules = [];
    let modified = false;

    // Backup clean binary only if backup doesn't exist OR if current binary is a brand-new unpatched update!
    const preCheck = inspectLanguageServerBinary(lsBinaryPath);
    if (!fs.existsSync(lsBakPath) || (!preCheck.isPatched && !preCheck.partiallyPatched)) {
        fs.copyFileSync(lsBinaryPath, lsBakPath);
    }

    if (arch === "x64" || arch === "universal") {
        for (const rule of X64_RULES) {
            const uOffs = findPatternOffsets(buf, rule.unpatched, 4);
            if (uOffs.length > 0) {
                for (const off of uOffs) {
                    rule.apply(buf, off);
                }
                modified = true;
                appliedRules.push({
                    id: rule.id,
                    status: "patched",
                    offsets: uOffs.map(o => `0x${o.toString(16)}`)
                });
            } else {
                const pOffs = findPatternOffsets(buf, rule.patched, 4);
                appliedRules.push({
                    id: rule.id,
                    status: pOffs.length > 0 ? "already_patched" : "pattern_not_found",
                    offsets: pOffs.map(o => `0x${o.toString(16)}`)
                });
            }
        }
    }

    if (arch === "arm64" || arch === "universal") {
        const armRes = scanAndPatchArm64CheckpointCap(buf, false);
        if (armRes.patchedHits > 0) {
            modified = true;
            appliedRules.push({ id: "arm64_checkpoint_cap_2m", status: "patched", count: armRes.patchedHits });
        } else if (armRes.alreadyPatchedHits > 0) {
            appliedRules.push({ id: "arm64_checkpoint_cap_2m", status: "already_patched", count: armRes.alreadyPatchedHits });
        }
    }

    if (modified) {
        const tmpPath = `${lsBinaryPath}.patching`;
        fs.writeFileSync(tmpPath, buf);
        try {
            if (process.platform !== "win32") {
                fs.chmodSync(tmpPath, 0o755);
            }
        } catch {}
        safeReplaceFileSync(tmpPath, lsBinaryPath);
        const signed = resignMacOsBinaryIfNeeded(lsBinaryPath);
        return { status: "patched", arch, codesigned: signed, appliedRules };
    }

    return { status: "already_patched", arch, appliedRules };
}

module.exports = {
    inspectLanguageServerBinary,
    patchLanguageServerBinary,
    safeReplaceFileSync,
    sleepSync
};
