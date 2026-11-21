"use strict";

/**
 * Antigravity Plus — 12-Language Instant Zero-Reload UI Localization Engine.
 * Languages: English (en), Persian (fa), Simplified Chinese (zh), Russian (ru),
 * Arabic (ar), Turkish (tr), Spanish (es), Brazilian Portuguese (pt),
 * Japanese (ja), Korean (ko), German (de), French (fr).
 */

const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const LOCALES_BR_PATH = path.join(__dirname, "locales.json.br");
const LOCALES_FILE_PATH = path.join(__dirname, "locales.json");

const SUPPORTED_LANGUAGES = [
    { code: "en", nativeName: "English", englishName: "English", rtl: false },
    { code: "fa", nativeName: "فارسی", englishName: "Persian", rtl: true },
    { code: "zh", nativeName: "简体中文", englishName: "Chinese (Simplified)", rtl: false },
    { code: "ru", nativeName: "Русский", englishName: "Russian", rtl: false },
    { code: "ar", nativeName: "العربية", englishName: "Arabic", rtl: true },
    { code: "tr", nativeName: "Türkçe", englishName: "Turkish", rtl: false },
    { code: "es", nativeName: "Español", englishName: "Spanish", rtl: false },
    { code: "pt", nativeName: "Português (Brasil)", englishName: "Portuguese", rtl: false },
    { code: "ja", nativeName: "日本語", englishName: "Japanese", rtl: false },
    { code: "ko", nativeName: "한국어", englishName: "Korean", rtl: false },
    { code: "de", nativeName: "Deutsch", englishName: "German", rtl: false },
    { code: "fr", nativeName: "Français", englishName: "French", rtl: false }
];

let _cachedLocalesMap = null;

function loadAllLocalesMap() {
    if (_cachedLocalesMap) return _cachedLocalesMap;
    try {
        if (fs.existsSync(LOCALES_BR_PATH)) {
            const raw = zlib.brotliDecompressSync(fs.readFileSync(LOCALES_BR_PATH)).toString("utf8");
            _cachedLocalesMap = JSON.parse(raw);
            return _cachedLocalesMap;
        }
        _cachedLocalesMap = JSON.parse(fs.readFileSync(LOCALES_FILE_PATH, "utf8"));
    } catch {
        _cachedLocalesMap = {};
    }
    return _cachedLocalesMap;
}

function getLocalePackByCode(langCode) {
    const code = String(langCode || "en").trim().toLowerCase();
    if (code === "en") {
        return { code: "en", rtl: false, meta: {}, dict: {} };
    }
    const all = loadAllLocalesMap();
    const pack = all[code];
    if (!pack) {
        return { code: "en", rtl: false, meta: {}, dict: {} };
    }
    return {
        code,
        rtl: Boolean(pack.rtl),
        meta: pack.meta || {},
        dict: pack.dict || {}
    };
}

function _agyInitMultiLanguageRuntime(gwBase, langsCatalog, getSyms) {
    var STORAGE_LANG_KEY = "agy.ui.language";
    var STORAGE_PACK_PREFIX = "agy.ui.pack.v3.";

    var _agyUiLang = (typeof window !== "undefined" && window.localStorage && window.localStorage.getItem(STORAGE_LANG_KEY)) || "en";
    var _agyActivePack = { code: "en", rtl: false, meta: {}, dict: {}, lower: Object.create(null) };
    var _agyPackMemCache = new Map();
    var _agyLangListeners = new Set();

    var _agyOrigText = typeof WeakMap !== "undefined" ? new WeakMap() : null;
    var _agyLastLocText = typeof WeakMap !== "undefined" ? new WeakMap() : null;
    var _agyOrigAttrs = typeof WeakMap !== "undefined" ? new WeakMap() : null;

    function _hydratePack(rawPack) {
        if (!rawPack || rawPack.code === "en") {
            return { code: "en", rtl: false, meta: {}, dict: {}, lower: Object.create(null) };
        }
        var lower = Object.create(null);
        var d = rawPack.dict || {};
        for (var k in d) {
            lower[k.toLowerCase()] = d[k];
        }
        return {
            code: rawPack.code,
            rtl: Boolean(rawPack.rtl),
            meta: rawPack.meta || {},
            dict: d,
            lower: lower
        };
    }

    // Load cached pack synchronously from localStorage if user previously chose a non-English language
    if (_agyUiLang !== "en" && typeof window !== "undefined" && window.localStorage) {
        try {
            var cachedRaw = window.localStorage.getItem(STORAGE_PACK_PREFIX + _agyUiLang);
            if (cachedRaw) {
                var hp = _hydratePack(JSON.parse(cachedRaw));
                _agyActivePack = hp;
                _agyPackMemCache.set(_agyUiLang, hp);
            }
        } catch (e) {}
    }

    function _agyStabilizeRtlBidi(rtlStr) {
        if (!rtlStr || !/[\u0590-\u08FF\uFB1D-\uFDFF\uFE70-\uFEFF]/.test(rtlStr)) return rtlStr;
        if (rtlStr.indexOf("\u2067") === 0) return rtlStr;
        var spaced = rtlStr.replace(/([A-Za-z0-9])(های|ها|یی)(?=[\s،.!:؟)\]]|$)/g, "$1 $2");
        var isolated = spaced.replace(
            /(?:\(\.\*\)|https?:\/\/[^\s)،]+|~\/[A-Za-z0-9_./-]+|(?:Ctrl|Alt|Shift|Cmd|Meta|Win)(?:\+[A-Za-z0-9↑↓←→↵⌫⌦⇥`\\/\[\];',.=-]+)+|\$\/[A-Za-z0-9]+|[A-Za-z0-9_$~+-]*[A-Za-z](?:[A-Za-z0-9_./:\\~+-]*[A-Za-z0-9/_~+-])?|[@/][A-Za-z0-9_-]*)/g,
            function (tok) { return "\u2066" + tok + "\u2069"; }
        );
        return "\u2067" + isolated + "\u2069";
    }

    function _agyLookupWordOrPhrase(s) {
        if (!s || _agyActivePack.code === "en") return null;
        if (_agyActivePack.dict[s]) return _agyActivePack.dict[s];
        var low = s.toLowerCase();
        if (_agyActivePack.lower[low]) return _agyActivePack.lower[low];
        return null;
    }

    function _agyTranslateDynamicRaw(str) {
        if (_agyActivePack.code === "en") return null;
        var meta = _agyActivePack.meta || {};
        var m;

        // 1. Version X.Y.Z in top-left Antigravity menu!
        if ((m = /^Version\s+([0-9A-Za-z._-]+)$/i.exec(str))) {
            var vp = meta.versionPrefix || "Version";
            return vp + " " + m[1];
        }
        // Top-left Antigravity (WSL: ...)
        if ((m = /^Antigravity\s+\(WSL:\s*(.+)\)$/i.exec(str))) {
            var brand = _agyLookupWordOrPhrase("Antigravity") || "Antigravity";
            return brand + " (WSL: " + m[1] + ")";
        }

        // 2. Chat input placeholder
        if (/^Ask anything,\s*@\s*to mention,\s*\/\s*for workflows$/i.test(str) || /^Ask anything.*@.*\/.*$/i.test(str)) {
            if (meta.placeholderAsk) return meta.placeholderAsk;
        }

        // 3. Quota / Context / Usage / Dynamic patterns across ALL 12 languages!
        if ((m = /^([\d.,KMB]+)\s*ctx\s*·\s*([\d.,KMB]+)\s*out$/i.exec(str))) {
            if (meta.ctxOutTemplate) {
                return meta.ctxOutTemplate.replace("{ctx}", m[1]).replace("{out}", m[2]);
            }
        }
        if ((m = /^([\d.,]+)\s*tok\/min\s*·\s*(\d+)\s*reqs?\s*·\s*([\d.,KMB]+)\s*ctx\s*·\s*([\d.,KMB]+)\s*out$/i.exec(str))) {
            var ctxPart = meta.ctxOutTemplate ? meta.ctxOutTemplate.replace("{ctx}", m[3]).replace("{out}", m[4]) : (m[3] + " ctx · " + m[4] + " out");
            if (_agyActivePack.code === "fa") {
                return m[1] + " توکن/دقیقه · " + m[2] + " درخواست · " + ctxPart;
            }
            return m[1] + " tok/min · " + m[2] + " req · " + ctxPart;
        }
        if ((m = /^([\d.,KMB]+)\s+of\s+([\d.,KMB]+)\s+tokens used$/i.exec(str))) {
            if (meta.tokensUsedTemplate) {
                return meta.tokensUsedTemplate.replace("{used}", m[1]).replace("{max}", m[2]);
            }
        }
        if ((m = /^(\d+)%\s+of the context window used$/i.exec(str)) && meta.pctWindowUsed) {
            return meta.pctWindowUsed.replace("{pct}", m[1]);
        }
        if ((m = /^Context window\s+(?:about\s+)?(\d+)%\s+full(.*)$/i.exec(str)) && meta.windowFull) {
            return meta.windowFull.replace("{pct}", m[1]);
        }
        if ((m = /^(\d+)%\s+left$/i.exec(str)) && meta.pctLeft) {
            return meta.pctLeft.replace("{pct}", m[1]);
        }
        if ((m = /^Configured in\s+(\S+)\s*·\s*(\S+)$/i.exec(str)) && meta.configuredIn) {
            return meta.configuredIn.replace("{path}", m[1]).replace("{url}", m[2]);
        }
        if (/^Google Gemini Max Plan & Custom JSON Providers$/i.test(str) && meta.maxPlanDesc) {
            return meta.maxPlanDesc;
        }
        if ((m = /^Thought for\s+(\d+(?:\.\d+)?)s$/i.exec(str)) && meta.thoughtFor) {
            return meta.thoughtFor.replace("{s}", m[1]);
        }
        if (/^No more older messages$/i.test(str) && meta.noMoreOlder) {
            return meta.noMoreOlder;
        }
        if ((m = /^(\d+)\s+accounts?\s*·\s*(\d+)\s+models?$/i.exec(str)) && meta.accModels) {
            return meta.accModels.replace("{a}", m[1]).replace("{m}", m[2]);
        }
        if ((m = /^Provider Models \((\d+) staged\)$/i.exec(str)) && meta.stagedModels) {
            return meta.stagedModels.replace("{n}", m[1]);
        }
        if ((m = /^gates\s+(.+?)\s+\+(\d+)\s+more$/i.exec(str)) && meta.gatesMore) {
            return meta.gatesMore.replace("{list}", m[1]).replace("{n}", m[2]);
        }
        if ((m = /^gates\s+(.+)$/i.exec(str)) && meta.gatesOne) {
            return meta.gatesOne.replace("{list}", m[1]);
        }
        if (str === "forced on" && meta.forcedOn) return meta.forcedOn;
        if (str === "forced off" && meta.forcedOff) return meta.forcedOff;
        if (_agyActivePack.code === "fa") {
            if (str === "Type") return "تایپ کنید";
            if (str === "and select") return "و انتخاب کنید";
        }
        if ((m = /^Your Plan:\s*(.+)$/i.exec(str))) {
            var yp = _agyLookupWordOrPhrase("Your Plan") || "Your Plan";
            return yp + ": " + m[1];
        }

        // 4. Direct dictionary lookup
        var direct = _agyLookupWordOrPhrase(str);
        if (direct) {
            if (_agyActivePack.code === "fa") {
                var mc = /^([\d.,KMB]+)\s*زمینه\s*·\s*([\d.,KMB]+)\s*خروجی$/.exec(direct);
                if (mc) return "کانتکست " + mc[1] + " · خروجی " + mc[2];
            }
            return direct;
        }

        // 5. Affix & counter rules (works across ALL 12 languages!)
        if (str.indexOf("+ ") === 0) {
            var rest = _agyLookupWordOrPhrase(str.slice(2).trim());
            if (rest) return "+ " + rest;
        }
        if (str.slice(-1) === ":" && str.length > 2) {
            var baseColon = _agyLookupWordOrPhrase(str.slice(0, -1).trim());
            if (baseColon) return baseColon + ":";
        }
        if (str.slice(-3) === "..." && str.length > 4) {
            var baseDots = _agyLookupWordOrPhrase(str.slice(0, -3).trim());
            if (baseDots) return baseDots + "...";
        }
        if ((m = /^(.+?)\s*\((\d+)\)$/.exec(str))) {
            var baseCnt = _agyLookupWordOrPhrase(m[1].trim());
            if (baseCnt) return baseCnt + " (" + m[2] + ")";
        }

        // 6. Relative timestamps across ALL 12 languages
        if (/^just now$/i.test(str) && meta.justNow) return meta.justNow;
        if (/^yesterday$/i.test(str) && meta.yesterday) return meta.yesterday;
        if (/^today$/i.test(str) && meta.today) return meta.today;
        if ((m = /^(\d+)\s*(?:s|sec|secs|seconds?)\s+ago$/i.exec(str)) && meta.secAgo) return meta.secAgo.replace("{n}", m[1]);
        if ((m = /^(\d+)\s*(?:m|min|mins|minutes?)\s+ago$/i.exec(str)) && meta.minAgo) return meta.minAgo.replace("{n}", m[1]);
        if ((m = /^(\d+)\s*(?:h|hr|hrs|hours?)\s+ago$/i.exec(str)) && meta.hourAgo) return meta.hourAgo.replace("{n}", m[1]);
        if ((m = /^(\d+)\s*(?:d|days?)\s+ago$/i.exec(str)) && meta.dayAgo) return meta.dayAgo.replace("{n}", m[1]);
        if ((m = /^(\d+)h$/i.exec(str)) && meta.shortH) return meta.shortH.replace("{n}", m[1]);
        if ((m = /^(\d+)m$/i.exec(str)) && meta.shortM) return meta.shortM.replace("{n}", m[1]);
        if ((m = /^(\d+)d$/i.exec(str)) && meta.shortD) return meta.shortD.replace("{n}", m[1]);

        return null;
    }

    function _agyTranslateDynamic(str) {
        var raw = _agyTranslateDynamicRaw(str);
        if (!raw) return null;
        return _agyActivePack.rtl ? _agyStabilizeRtlBidi(raw) : raw;
    }

    function _agyIsInlineOnlyProseContainer(el) {
        if (!el || !el.children) return false;
        var tag = el.tagName;
        if (tag === "BUTTON" || tag === "NAV" || tag === "UL" || tag === "OL" || tag === "TABLE" || tag === "TR") return false;
        var cls = typeof el.className === "string" ? el.className : "";
        if (/\bflex\b|\bgrid\b|\binline-flex\b/.test(cls)) return false;
        for (var i = 0; i < el.children.length; i++) {
            var ct = el.children[i].tagName;
            if (ct !== "SPAN" && ct !== "CODE" && ct !== "A" && ct !== "STRONG" && ct !== "EM" && ct !== "B" && ct !== "I" && ct !== "KBD") {
                return false;
            }
        }
        return true;
    }

    function _agyShouldSkipNode(el) {
        if (!el || !el.closest) return true;
        var tag = el.tagName;
        if (tag === "PRE" || tag === "CODE" || tag === "SCRIPT" || tag === "STYLE" || tag === "TEXTAREA" || tag === "SVG" || tag === "OPTION") return true;
        if (el.closest('pre, code, script, style, textarea, [data-testid="appearance-language-select"], [data-testid="appearance-language-popover"], [contenteditable="true"], [data-testid="turn-cards-container"], [data-testid="user-message-bubble"], [data-testid="planner-response-text"], .monaco-editor, .xterm')) return true;
        return false;
    }

    function _agyApplyDomLocalization(rootEl) {
        if (typeof document === "undefined" || !document.body || !_agyOrigText) return;
        var scope = rootEl && rootEl.nodeType === 1 ? rootEl : document.body;
        var isEn = _agyUiLang === "en" || _agyActivePack.code === "en";
        var isRtl = !isEn && _agyActivePack.rtl;
        document.documentElement.setAttribute("data-agy-lang", _agyUiLang);

        var walker = document.createTreeWalker(scope, NodeFilter.SHOW_TEXT, null);
        var node;
        while ((node = walker.nextNode())) {
            var parent = node.parentElement;
            if (_agyShouldSkipNode(parent)) continue;
            var curVal = node.nodeValue;
            if (!curVal || !curVal.trim()) continue;

            // Recover true original English text even when switching directly from Lang A -> Lang B!
            var prevLoc = _agyLastLocText.get(node);
            var baseEn;
            if (_agyOrigText.has(node) && prevLoc === curVal) {
                baseEn = _agyOrigText.get(node);
            } else {
                baseEn = curVal;
                _agyOrigText.set(node, curVal);
            }

            if (!isEn) {
                var tr = _agyTranslateDynamic(baseEn.trim());
                if (tr) {
                    var lead = /^\s*/.exec(baseEn)[0];
                    var trail = /\s*$/.exec(baseEn)[0];
                    var nextStr = lead + tr + trail;
                    _agyLastLocText.set(node, nextStr);
                    if (curVal !== nextStr) node.nodeValue = nextStr;
                    if (parent) {
                        if (isRtl && (parent.childElementCount === 0 || _agyIsInlineOnlyProseContainer(parent))) {
                            parent.setAttribute("data-agy-bidi", "rtl");
                        } else if (!isRtl && parent.hasAttribute("data-agy-bidi")) {
                            parent.removeAttribute("data-agy-bidi");
                        }
                    }
                } else {
                    if (curVal !== baseEn) node.nodeValue = baseEn;
                    _agyLastLocText.delete(node);
                    if (parent && parent.hasAttribute("data-agy-bidi")) parent.removeAttribute("data-agy-bidi");
                }
            } else {
                if (prevLoc === curVal && curVal !== baseEn) {
                    node.nodeValue = baseEn;
                }
                _agyLastLocText.delete(node);
                if (parent && parent.hasAttribute("data-agy-bidi")) {
                    parent.removeAttribute("data-agy-bidi");
                }
            }
        }

        var attrEls = scope.querySelectorAll ? scope.querySelectorAll("input[placeholder], textarea[placeholder], [title], [aria-label]") : [];
        for (var i = 0; i < attrEls.length; i++) {
            var el = attrEls[i];
            if (el.tagName !== "TEXTAREA" && _agyShouldSkipNode(el)) continue;
            var saved = _agyOrigAttrs.get(el) || {};
            var attrs = ["placeholder", "title", "aria-label"];
            for (var ai = 0; ai < attrs.length; ai++) {
                var aName = attrs[ai];
                var val = el.getAttribute(aName);
                if (!val) continue;
                var baseAttr = saved[aName] || val;
                if (!saved[aName]) {
                    saved[aName] = val;
                    _agyOrigAttrs.set(el, saved);
                }
                if (!isEn) {
                    var trAttr = _agyTranslateDynamic(baseAttr.trim());
                    var targetAttr = trAttr || baseAttr;
                    if (val !== targetAttr) el.setAttribute(aName, targetAttr);
                } else if (val !== baseAttr) {
                    el.setAttribute(aName, baseAttr);
                }
            }
        }
    }

    var _agyLocScheduled = false;
    function _agyScheduleDomLocalization() {
        if (_agyLocScheduled) return;
        _agyLocScheduled = true;
        requestAnimationFrame(function () {
            _agyLocScheduled = false;
            try { _agyApplyDomLocalization(document.body); } catch (e) {}
        });
    }

    async function _agyLoadPackIfNeeded(code) {
        if (code === "en") return { code: "en", rtl: false, meta: {}, dict: {}, lower: Object.create(null) };
        if (_agyPackMemCache.has(code)) return _agyPackMemCache.get(code);
        try {
            var r = await fetch(gwBase + "/__agy_i18n/get?lang=" + encodeURIComponent(code));
            var raw = await r.json();
            try { window.localStorage.setItem(STORAGE_PACK_PREFIX + code, JSON.stringify(raw)); } catch (e) {}
            var hydrated = _hydratePack(raw);
            _agyPackMemCache.set(code, hydrated);
            return hydrated;
        } catch (e) {
            return { code: "en", rtl: false, meta: {}, dict: {}, lower: Object.create(null) };
        }
    }

    async function _agySetUiLanguage(nextLang) {
        var code = String(nextLang || "en").trim().toLowerCase();
        _agyUiLang = code;
        try { window.localStorage.setItem(STORAGE_LANG_KEY, code); } catch (e) {}
        _agyActivePack = await _agyLoadPackIfNeeded(code);
        _agyLangListeners.forEach(function (fn) { try { fn(code, _agyActivePack); } catch (e) {} });
        _agyApplyDomLocalization(document.body);
    }

    // Refresh cached pack from server in background on boot if non-English is active
    if (_agyUiLang !== "en" && typeof window !== "undefined") {
        _agyLoadPackIfNeeded(_agyUiLang).then(function (pk) {
            _agyActivePack = pk;
            _agyScheduleDomLocalization();
        }).catch(function () {});
    }

    if (typeof window !== "undefined") {
        window.__agySetUiLanguage = _agySetUiLanguage;
        window.__agyGetUiLanguage = function () { return _agyUiLang; };
        window.__agyApplyDomLocalization = _agyApplyDomLocalization;
        window.__agyScheduleDomLocalization = _agyScheduleDomLocalization;
        window.addEventListener("pointerdown", function () { if (_agyUiLang !== "en") setTimeout(_agyScheduleDomLocalization, 16); }, true);
        window.addEventListener("focusin", function () { if (_agyUiLang !== "en") _agyScheduleDomLocalization(); }, true);
    }

    function AppearanceLanguageCard() {
        var _s = getSyms();
        var A = _s.A, ReactDOMPortal = _s.Portal, YP = _s.YP, WP = _s.WP, XP = _s.XP;
        var st = A.useState(_agyUiLang);
        var lang = st[0], setLang = st[1];
        var stMeta = A.useState(_agyActivePack.meta || {});
        var meta = stMeta[0], setMeta = stMeta[1];
        var stOpen = A.useState(false);
        var open = stOpen[0], setOpen = stOpen[1];
        var stQuery = A.useState("");
        var query = stQuery[0], setQuery = stQuery[1];
        var stPos = A.useState({ top: 0, left: 0, openUp: false });
        var pos = stPos[0], setPos = stPos[1];
        var btnRef = A.useRef(null);
        var popRef = A.useRef(null);
        var searchRef = A.useRef(null);

        A.useEffect(function () {
            var cb = function (l, pk) {
                setLang(l);
                setMeta((pk && pk.meta) || {});
            };
            _agyLangListeners.add(cb);
            return function () { _agyLangListeners.delete(cb); };
        }, []);

        A.useEffect(function () {
            if (!open) return;
            setTimeout(function () { if (searchRef.current) searchRef.current.focus(); }, 20);
            var onDocDown = function (ev) {
                if (btnRef.current && btnRef.current.contains(ev.target)) return;
                if (popRef.current && popRef.current.contains(ev.target)) return;
                setOpen(false);
                setQuery("");
            };
            var onKey = function (ev) {
                if (ev.key === "Escape") {
                    setOpen(false);
                    setQuery("");
                }
            };
            document.addEventListener("mousedown", onDocDown, true);
            window.addEventListener("keydown", onKey, true);
            window.addEventListener("resize", onDocDown);
            return function () {
                document.removeEventListener("mousedown", onDocDown, true);
                window.removeEventListener("keydown", onKey, true);
                window.removeEventListener("resize", onDocDown);
            };
        }, [open]);

        var toggleOpen = function () {
            if (open) {
                setOpen(false);
                setQuery("");
                return;
            }
            if (btnRef.current) {
                var r = btnRef.current.getBoundingClientRect();
                var menuW = 268;
                var menuH = 330;
                var spaceBelow = window.innerHeight - r.bottom;
                var openUp = spaceBelow < menuH && r.top > menuH;
                var leftPx = Math.max(12, Math.min(window.innerWidth - menuW - 12, r.right - menuW));
                setPos({
                    top: openUp ? Math.max(12, r.top - 6) : (r.bottom + 6),
                    left: leftPx,
                    openUp: openUp
                });
            }
            setQuery("");
            setOpen(true);
        };

        var activeItem = langsCatalog.find(function (x) { return x.code === lang; }) || langsCatalog[0];
        var qLow = query.trim().toLowerCase();
        var filtered = langsCatalog.filter(function (x) {
            if (!qLow) return true;
            return x.nativeName.toLowerCase().indexOf(qLow) !== -1 ||
                   x.englishName.toLowerCase().indexOf(qLow) !== -1 ||
                   x.code.toLowerCase().indexOf(qLow) !== -1;
        });

        var isEn = lang === "en";
        var cardTitle = (!isEn && meta.languageCardTitle) || "Language";
        var rowLabel = (!isEn && meta.interfaceLanguageLabel) || "Interface Language";
        var rowDesc = (!isEn && meta.interfaceLanguageDesc) || "Switch the entire application interface, menus, settings, and dialogs across 12 languages with zero reload.";

        var globeIcon = A.createElement("svg", { viewBox: "0 0 24 24", width: 14, height: 14, fill: "none", stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round", strokeLinejoin: "round", className: "text-muted-foreground shrink-0" },
            A.createElement("circle", { cx: 12, cy: 12, r: 10 }),
            A.createElement("path", { d: "M2 12h20" }),
            A.createElement("path", { d: "M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" })
        );

        var chevronIcon = A.createElement("svg", { viewBox: "0 0 20 20", width: 14, height: 14, fill: "currentColor", className: "text-muted-foreground shrink-0 transition-transform duration-150 " + (open ? "rotate-180" : "") },
            A.createElement("path", { fillRule: "evenodd", d: "M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z", clipRule: "evenodd" })
        );

        var checkIcon = A.createElement("svg", { viewBox: "0 0 20 20", width: 14, height: 14, fill: "currentColor", className: "text-primary shrink-0" },
            A.createElement("path", { fillRule: "evenodd", d: "M16.704 4.153a.75.75 0 01.143 1.052l-8 10.5a.75.75 0 01-1.127.075l-4.5-4.5a.75.75 0 011.06-1.06l3.894 3.893 7.48-9.817a.75.75 0 011.05-.143z", clipRule: "evenodd" })
        );

        return A.createElement(YP, { title: cardTitle },
            A.createElement(WP, null,
                A.createElement(XP, {
                    label: rowLabel,
                    description: rowDesc,
                    rightElement: A.createElement("div", { className: "relative", "data-testid": "appearance-language-select" },
                        A.createElement("button", {
                            ref: btnRef,
                            type: "button",
                            "data-testid": "appearance-language-trigger",
                            onClick: toggleOpen,
                            className: "h-8 pl-2.5 pr-2 rounded-lg border border-border bg-secondary/40 hover:bg-secondary/80 text-xs font-medium text-foreground inline-flex items-center justify-between gap-2 min-w-[168px] transition-colors cursor-pointer select-none outline-none focus-visible:ring-1 focus-visible:ring-primary"
                        },
                            A.createElement("span", { className: "inline-flex items-center gap-2 min-w-0" },
                                globeIcon,
                                A.createElement("span", { className: "truncate" }, activeItem.nativeName)
                            ),
                            A.createElement("span", { className: "inline-flex items-center gap-1.5 shrink-0" },
                                A.createElement("span", { className: "px-1.5 py-0.5 rounded bg-muted/80 border border-border/60 font-mono text-[10px] uppercase text-muted-foreground leading-none" }, activeItem.code),
                                chevronIcon
                            )
                        ),

                        open && (function () {
                            var popEl = A.createElement("div", {
                                ref: popRef,
                                "data-testid": "appearance-language-popover",
                                style: {
                                    position: "fixed",
                                    top: pos.openUp ? "auto" : (pos.top + "px"),
                                    bottom: pos.openUp ? ((window.innerHeight - pos.top) + "px") : "auto",
                                    left: pos.left + "px",
                                    width: "268px",
                                    zIndex: 99999
                                },
                                className: "rounded-xl border border-border bg-background shadow-2xl overflow-hidden flex flex-col"
                            },
                                A.createElement("div", { className: "p-2 border-b border-border/70 bg-muted/20" },
                                    A.createElement("input", {
                                        ref: searchRef,
                                        type: "text",
                                        value: query,
                                        onChange: function (e) { setQuery(e.target.value); },
                                        placeholder: lang === "fa" ? "جستجوی زبان..." : "Search language...",
                                        className: "w-full h-7 px-2.5 rounded-md !bg-muted/70 !border !border-border text-xs text-foreground outline-none focus:!ring-1 focus:!ring-primary"
                                    })
                                ),
                                A.createElement("div", { className: "max-h-60 overflow-y-auto p-1.5 flex flex-col gap-0.5" },
                                    filtered.length === 0
                                        ? A.createElement("div", { className: "py-4 text-center text-xs text-muted-foreground" }, "No matching language")
                                        : filtered.map(function (item) {
                                            var selected = item.code === lang;
                                            return A.createElement("button", {
                                                key: item.code,
                                                type: "button",
                                                "data-testid": "lang-opt-" + item.code,
                                                onClick: function () {
                                                    setOpen(false);
                                                    setQuery("");
                                                    void _agySetUiLanguage(item.code);
                                                },
                                                className: "w-full px-2.5 py-1.5 rounded-lg border-none text-left flex items-center justify-between gap-2 cursor-pointer transition-colors " + (selected ? "bg-primary/15 text-foreground" : "bg-transparent hover:bg-secondary text-foreground/90")
                                            },
                                                A.createElement("div", { className: "flex items-center gap-2.5 min-w-0" },
                                                    A.createElement("span", { className: "w-6 h-5 rounded bg-muted border border-border/70 inline-flex items-center justify-center font-mono text-[10px] uppercase text-muted-foreground shrink-0" }, item.code),
                                                    A.createElement("div", { className: "flex flex-col min-w-0 leading-tight" },
                                                        A.createElement("span", { className: "text-xs font-medium text-foreground truncate" }, item.nativeName),
                                                        item.code !== "en" && A.createElement("span", { className: "text-[10px] text-muted-foreground truncate" }, item.englishName)
                                                    )
                                                ),
                                                selected ? checkIcon : null
                                            );
                                        })
                                )
                            );
                            return (ReactDOMPortal && typeof ReactDOMPortal.createPortal === "function" && typeof document !== "undefined" && document.body)
                                ? ReactDOMPortal.createPortal(popEl, document.body)
                                : popEl;
                        })()
                    )
                })
            )
        );
    }

    return AppearanceLanguageCard;
}

function buildAppearanceLanguageAndI18nCode(gwBase, syms = {}) {
    const langsJson = JSON.stringify(SUPPORTED_LANGUAGES);
    const R = syms.reactSym || "A";
    const P = syms.portalSym || "uy";
    const YP = syms.sectionCardSym || "YP";
    const WP = syms.cardContainerSym || "WP";
    const XP = syms.cardRowSym || "XP";
    return `\nvar _AgyAppearanceLanguageCard = (${_agyInitMultiLanguageRuntime.toString()})(${JSON.stringify(gwBase)}, ${langsJson}, function(){ return { A: ${R}, Portal: typeof ${P}!=="undefined"?${P}:null, YP: ${YP}, WP: ${WP}, XP: ${XP} }; });\n`;
}

module.exports = {
    SUPPORTED_LANGUAGES,
    getLocalePackByCode,
    buildAppearanceLanguageAndI18nCode
};
