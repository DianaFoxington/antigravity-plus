"use strict";

/**
 * Pure Node.js Electron ASAR archive reader & extractor.
 * Zero external dependencies — supports packed files, unpacked sidecar dirs, and Unix executable bits.
 */

const fs = require("fs");
const path = require("path");

function parseAsarHeader(fd) {
    const preBuf = Buffer.alloc(16);
    const readBytes = fs.readSync(fd, preBuf, 0, 16, 0);
    if (readBytes < 16) {
        throw new Error("Invalid ASAR archive (header truncated)");
    }
    const headerSize = preBuf.readUInt32LE(4);
    const jsonSize = preBuf.readUInt32LE(12);
    const dataOffset = 8 + headerSize;

    const jsonBuf = Buffer.alloc(jsonSize);
    fs.readSync(fd, jsonBuf, 0, jsonSize, 16);
    const jsonStr = jsonBuf.toString("utf8").replace(/\0+$/, "");
    const header = JSON.parse(jsonStr);
    return { header, dataOffset };
}

function copyDirRecursive(src, dst) {
    if (!fs.existsSync(src)) return;
    fs.mkdirSync(dst, { recursive: true });
    for (const ent of fs.readdirSync(src, { withFileTypes: true })) {
        const s = path.join(src, ent.name);
        const d = path.join(dst, ent.name);
        if (ent.isDirectory()) {
            copyDirRecursive(s, d);
        } else if (ent.isSymbolicLink()) {
            try {
                const linkTarget = fs.readlinkSync(s);
                if (fs.existsSync(d)) fs.unlinkSync(d);
                fs.symlinkSync(linkTarget, d);
            } catch {}
        } else {
            fs.copyFileSync(s, d);
            try {
                fs.chmodSync(d, fs.statSync(s).mode);
            } catch {}
        }
    }
}

function removeDirRecursive(targetDir) {
    if (!fs.existsSync(targetDir)) return;
    fs.rmSync(targetDir, { recursive: true, force: true });
}

function extractAsarArchive(asarFilePath, destAppDir, unpackedSidecarDir = null) {
    if (!fs.existsSync(asarFilePath)) {
        throw new Error(`ASAR archive not found: ${asarFilePath}`);
    }

    const fd = fs.openSync(asarFilePath, "r");
    let extractedCount = 0;
    try {
        const { header, dataOffset } = parseAsarHeader(fd);
        if (fs.existsSync(destAppDir)) {
            removeDirRecursive(destAppDir);
        }
        fs.mkdirSync(destAppDir, { recursive: true });

        const walk = (node, relPrefix) => {
            const filesObj = node && node.files ? node.files : {};
            for (const [name, meta] of Object.entries(filesObj)) {
                const relPath = relPrefix ? path.join(relPrefix, name) : name;
                const outPath = path.join(destAppDir, relPath);

                if (meta && meta.files) {
                    fs.mkdirSync(outPath, { recursive: true });
                    walk(meta, relPath);
                    continue;
                }

                if (meta && meta.link) {
                    fs.mkdirSync(path.dirname(outPath), { recursive: true });
                    try {
                        fs.symlinkSync(meta.link, outPath);
                    } catch {}
                    continue;
                }

                if (meta && meta.unpacked) {
                    if (unpackedSidecarDir) {
                        const unpackedSrc = path.join(unpackedSidecarDir, relPath);
                        if (fs.existsSync(unpackedSrc)) {
                            fs.mkdirSync(path.dirname(outPath), { recursive: true });
                            fs.copyFileSync(unpackedSrc, outPath);
                            if (meta.executable && process.platform !== "win32") {
                                try { fs.chmodSync(outPath, 0o755); } catch {}
                            }
                            extractedCount++;
                        }
                    }
                    continue;
                }

                const size = Number(meta.size || 0);
                const offset = Number(meta.offset || 0);
                fs.mkdirSync(path.dirname(outPath), { recursive: true });

                const outFd = fs.openSync(outPath, "w");
                try {
                    const chunkSize = 1024 * 1024;
                    const buf = Buffer.allocUnsafe(Math.min(size || 1, chunkSize));
                    let remaining = size;
                    let pos = dataOffset + offset;
                    while (remaining > 0) {
                        const toRead = Math.min(remaining, buf.length);
                        const n = fs.readSync(fd, buf, 0, toRead, pos);
                        if (n <= 0) break;
                        fs.writeSync(outFd, buf, 0, n);
                        pos += n;
                        remaining -= n;
                    }
                } finally {
                    fs.closeSync(outFd);
                }

                if (meta.executable && process.platform !== "win32") {
                    try { fs.chmodSync(outPath, 0o755); } catch {}
                }
                extractedCount++;
            }
        };

        walk(header, "");
    } finally {
        fs.closeSync(fd);
    }

    return { extractedCount };
}

function readSingleFileFromAsar(asarFilePath, targetRelPosixPath) {
    if (!fs.existsSync(asarFilePath)) return null;
    const fd = fs.openSync(asarFilePath, "r");
    try {
        const { header, dataOffset } = parseAsarHeader(fd);
        const parts = targetRelPosixPath.split("/").filter(Boolean);
        let cur = header;
        for (let i = 0; i < parts.length; i++) {
            if (!cur || !cur.files || !cur.files[parts[i]]) return null;
            cur = cur.files[parts[i]];
        }
        if (!cur || cur.files || cur.unpacked) return null;
        const size = Number(cur.size || 0);
        const offset = Number(cur.offset || 0);
        const buf = Buffer.alloc(size);
        fs.readSync(fd, buf, 0, size, dataOffset + offset);
        return buf;
    } finally {
        fs.closeSync(fd);
    }
}

module.exports = {
    extractAsarArchive,
    readSingleFileFromAsar,
    copyDirRecursive,
    removeDirRecursive
};
