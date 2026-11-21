"use strict";
const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const url = require("url");
const crypto = require("crypto");
const magis = require("./magis.js");
const dnsx = require("./dnsx.js");

const PORT = process.env.PORT || 3080;

const streamTokens = new Map();

function registerStream(targetUrl, headers, isLive, extra) {
  const token = crypto.randomBytes(10).toString("hex");
  streamTokens.set(token, Object.assign({
    url: targetUrl,
    headers: headers || {},
    isLive: !!isLive,
    at: Date.now()
  }, extra || {}));
  if (streamTokens.size > 60) {
    const oldest = streamTokens.keys().next().value;
    streamTokens.delete(oldest);
  }
  return token;
}

function swapTsPids(buf, pidA, pidB) {
  if (!pidA || !pidB || pidA === pidB) return buf;
  for (let off = 0; off + 188 <= buf.length; off += 188) {
    if (buf[off] !== 0x47) continue;
    const pid = ((buf[off + 1] & 0x1f) << 8) | buf[off + 2];
    let nextPid = -1;
    if (pid === pidA) nextPid = pidB;
    else if (pid === pidB) nextPid = pidA;
    if (nextPid >= 0) {
      buf[off + 1] = (buf[off + 1] & 0xe0) | ((nextPid >> 8) & 0x1f);
      buf[off + 2] = nextPid & 0xff;
    }
  }
  return buf;
}

function fetchRangeBuffer(targetUrl, customHeaders, startByte, endByte) {
  return new Promise((resolve, reject) => {
    const parsed = url.parse(targetUrl);
    const isHttps = parsed.protocol === "https:";
    const host = parsed.hostname;
    dnsx.resolve(host, (dErr, dRes) => {
      const ip = (!dErr && dRes && dRes.ips && dRes.ips[0]) || host;
      const reqHeaders = Object.assign({}, customHeaders || {}, {
        Host: parsed.host,
        Range: `bytes=${startByte}-${endByte}`
      });
      const req = (isHttps ? https : http).request({
        hostname: ip,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.path,
        method: "GET",
        servername: host,
        rejectUnauthorized: false,
        headers: reqHeaders,
        timeout: 15000
      }, (resp) => {
        if (resp.statusCode >= 300 && resp.statusCode < 400 && resp.headers.location) {
          resp.resume();
          return fetchRangeBuffer(url.resolve(targetUrl, resp.headers.location), customHeaders, startByte, endByte).then(resolve, reject);
        }
        const chunks = [];
        resp.on("data", c => chunks.push(c));
        resp.on("end", () => {
          const cr = String(resp.headers["content-range"] || "");
          const m = /\/(\d+)$/.exec(cr);
          const totalLen = m ? parseInt(m[1], 10) : parseInt(resp.headers["content-length"] || "0", 10);
          resolve({ status: resp.statusCode, totalLen, buf: Buffer.concat(chunks) });
        });
      });
      req.on("error", reject);
      req.end();
    });
  });
}

async function probeTsInfo(targetUrl, headers) {
  try {
    const { totalLen, buf } = await fetchRangeBuffer(targetUrl, headers, 0, 18799);
    let pmtPid = -1;
    let patPacket = null;
    let pmtPacket = null;
    const audioPids = [];
    const AUDIO_TYPES = new Set([0x03, 0x04, 0x0f, 0x11, 0x81, 0x82, 0x86, 0x87]);
    for (let off = 0; off + 188 <= buf.length; off += 188) {
      if (buf[off] !== 0x47) continue;
      const pid = ((buf[off + 1] & 0x1f) << 8) | buf[off + 2];
      const pusi = (buf[off + 1] & 0x40) !== 0;
      const afc = (buf[off + 3] >> 4) & 0x3;
      let pos = off + 4;
      if (afc === 2) continue;
      if (afc === 3) pos += 1 + buf[pos];
      if (pusi) pos += 1 + buf[pos];
      if (pid === 0 && pmtPid < 0) {
        patPacket = Buffer.from(buf.subarray(off, off + 188));
        const secLen = ((buf[pos + 1] & 0x0f) << 8) | buf[pos + 2];
        const end = Math.min(off + 188, pos + 3 + secLen - 4);
        for (let p = pos + 8; p + 4 <= end; p += 4) {
          const progNum = (buf[p] << 8) | buf[p + 1];
          if (progNum !== 0) {
            pmtPid = ((buf[p + 2] & 0x1f) << 8) | buf[p + 3];
            break;
          }
        }
      } else if (pid === pmtPid && !pmtPacket) {
        pmtPacket = Buffer.from(buf.subarray(off, off + 188));
        const secLen = ((buf[pos + 1] & 0x0f) << 8) | buf[pos + 2];
        const progInfoLen = ((buf[pos + 10] & 0x0f) << 8) | buf[pos + 11];
        const end = Math.min(off + 188, pos + 3 + secLen - 4);
        let p = pos + 12 + progInfoLen;
        while (p + 5 <= end) {
          const stType = buf[p];
          const esPid = ((buf[p + 1] & 0x1f) << 8) | buf[p + 2];
          const esInfoLen = ((buf[p + 3] & 0x0f) << 8) | buf[p + 4];
          if (AUDIO_TYPES.has(stType) && !audioPids.includes(esPid)) audioPids.push(esPid);
          p += 5 + esInfoLen;
        }
        break;
      }
    }
    return { totalLen: totalLen || 0, audioPids, patPacket, pmtPacket };
  } catch (_) {
    return { totalLen: 0, audioPids: [], patPacket: null, pmtPacket: null };
  }
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Cache-Control": "no-store"
  });
  res.end(body);
}

function proxyRequest(targetUrl, customHeaders, clientReq, clientRes, onBodyTransform) {
  const parsed = url.parse(targetUrl);
  const isHttps = parsed.protocol === "https:";
  const host = parsed.hostname;
  if (!host) {
    clientRes.writeHead(502);
    return clientRes.end("Invalid upstream host");
  }

  dnsx.resolve(host, (dErr, dRes) => {
    const ip = (!dErr && dRes && dRes.ips && dRes.ips[0]) || host;
    const reqHeaders = Object.assign({}, customHeaders || {}, {
      Host: parsed.host
    });
    if (clientReq.headers.range && !onBodyTransform) {
      reqHeaders.Range = clientReq.headers.range;
    }

    const options = {
      hostname: ip,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.path,
      method: "GET",
      servername: host,
      rejectUnauthorized: false,
      headers: reqHeaders,
      timeout: 15000
    };

    const upReq = (isHttps ? https : http).request(options, (upRes) => {
      if (
        upRes.statusCode >= 300 &&
        upRes.statusCode < 400 &&
        upRes.headers.location
      ) {
        const nextUrl = url.resolve(targetUrl, upRes.headers.location);
        upRes.resume();
        return proxyRequest(nextUrl, customHeaders, clientReq, clientRes, onBodyTransform);
      }

      if (onBodyTransform) {
        const chunks = [];
        upRes.on("data", (c) => chunks.push(c));
        upRes.on("end", () => {
          const rawText = Buffer.concat(chunks).toString("utf8");
          onBodyTransform(upRes.statusCode || 200, upRes.headers, rawText);
        });
        return;
      }

      const outHeaders = {
        "Content-Type": upRes.headers["content-type"] || "video/mp2t",
        "Accept-Ranges": upRes.headers["accept-ranges"] || "bytes",
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "no-store"
      };
      if (upRes.headers["content-length"]) outHeaders["Content-Length"] = upRes.headers["content-length"];
      if (upRes.headers["content-range"]) outHeaders["Content-Range"] = upRes.headers["content-range"];

      clientRes.writeHead(upRes.statusCode || 200, outHeaders);
      upRes.pipe(clientRes);
      clientReq.on("close", () => {
        try { upRes.destroy(); } catch (_) {}
      });
    });

    upReq.on("error", (err) => {
      if (!clientRes.headersSent) {
        clientRes.writeHead(502, { "Content-Type": "text/plain", "Access-Control-Allow-Origin": "*" });
        clientRes.end("Upstream error: " + err.message);
      }
    });
    upReq.end();
  });
}

const SHELF_IDS = {
  movies: {
    "2026": 76264,
    "2026_teatrales": 79105,
    "all": 76263,
    "acción": 76275,
    "comedia": 76274,
    "crimen": 76272,
    "terror": 76273,
    "horror": 76273,
    "familia": 76277,
    "fantasía": 76278,
    "historia": 76279,
    "misterio": 76281,
    "romance": 76282,
    "suspenso": 76283,
    "ciencia ficción": 76286,
    "biografía": 76287,
    "documental": 88832,
    "aventura": 76288,
    "hbo": 76266,
    "prime video": 76267,
    "apple tv+": 76268
  },
  series: {
    "2026": 76237,
    "all": 76235,
    "drama": 76245,
    "familia": 76254,
    "fantasía": 76249,
    "historia": 76250,
    "misterio": 76248,
    "romance": 76251,
    "suspenso": 76252,
    "guerra": 76256,
    "ciencia ficción": 76258,
    "biografía": 76255,
    "documental": 88831,
    "crimen": 76259,
    "terror": 76260,
    "horror": 76260,
    "comedia": 76262,
    "telenovelas": 76236,
    "serie turquía": 84219,
    "drama coreano": 79106,
    "hbo": 76243,
    "prime video": 76238
  }
};

function mapShelveAsset(a, defaultKind, rowLabel) {
  if (!a || !a.contentId) return null;
  const posterList = Array.isArray(a.posterList) ? a.posterList : [];
  const pickImg = (t) => {
    const f = posterList.find(p => p && p.fileType === t && p.fileUrl);
    return f ? String(f.fileUrl).trim() : "";
  };
  const poster = pickImg("icon") || pickImg("poster") || a.posterUrl || "";
  const backdrop = pickImg("stage") || pickImg("poster") || poster;
  const rel = String(a.releaseTime || a.releaseDate || "").trim();
  const yr = /^\d{4}/.test(rel) ? rel.slice(0, 4) : "";
  const isSer = a.programType === "teleplay" || a.programType === "series" || defaultKind === "series";
  const genres = String(a.tags || "").split(",").map(s => s.trim()).filter(Boolean);
  return {
    id: String(a.contentId),
    title: String(a.name || a.title || ""),
    kind: isSer ? "series" : "movie",
    year: yr,
    releaseDate: rel,
    score: a.score != null ? String(a.score) : "",
    duration: String(a.duration || ""),
    genres,
    synopsis: String(a.description || a.synopsis || ""),
    poster,
    backdrop,
    row: rowLabel || ""
  };
}

function fetchShelve(columnId, pageNum, pageSize, defaultKind, rowLabel) {
  return new Promise((resolve) => {
    magis.call(
      "v3/getShelveData",
      {
        columnId: Number(columnId),
        columnType: "2",
        pageSize: pageSize || 100,
        pageNum: pageNum || 1,
        numDisplay: null,
        encryptVersion: 0
      },
      (err, data) => {
        if (err || !data || !Array.isArray(data.assetList)) {
          return resolve({ items: [], total: 0 });
        }
        const items = data.assetList.map(a => mapShelveAsset(a, defaultKind, rowLabel)).filter(Boolean);
        resolve({ items, total: data.assetListTotalSize || items.length });
      }
    );
  });
}

// Load Custom VOD M3U backup list (shared across Web & Roku when portal VOD is paused)
const CUSTOM_VOD_FILE = path.join(__dirname, "custom_vod.json");
const PROXY_CONFIG_FILE = path.join(__dirname, "proxy_config.json");
let customVodState = { m3uUrl: "", items: [] };
try {
  const saved = JSON.parse(fs.readFileSync(CUSTOM_VOD_FILE, "utf8"));
  if (saved && Array.isArray(saved.items)) customVodState = saved;
} catch (_) {}
try {
  const savedProxy = JSON.parse(fs.readFileSync(PROXY_CONFIG_FILE, "utf8"));
  if (savedProxy && savedProxy.proxyUrl) magis.setManualProxy(savedProxy.proxyUrl);
} catch (_) {}

function saveProxyConfig(proxyUrl) {
  try { fs.writeFileSync(PROXY_CONFIG_FILE, JSON.stringify({ proxyUrl: String(proxyUrl || "") }, null, 2)); } catch (_) {}
}

function saveCustomVod() {
  try { fs.writeFileSync(CUSTOM_VOD_FILE, JSON.stringify(customVodState, null, 2)); } catch (_) {}
}

function readJsonBody(req, cb) {
  let body = "";
  req.on("data", chunk => { body += chunk; if (body.length > 512000) req.destroy(); });
  req.on("end", () => {
    try { cb(null, JSON.parse(body || "{}")); } catch (e) { cb(e); }
  });
}

// Auto-refresh seeds in background every 15 min if portal session is not active
setInterval(() => {
  if (!magis.session || !magis.session.ready) {
    try { magis.forceRefreshSeeds(() => {}); } catch (_) {}
  }
}, 15 * 60 * 1000);

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname || "/";

  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "*"
    });
    return res.end();
  }

  // API: Shelve Pagination (v3/getShelveData with real releaseTime!)
  if (pathname === "/api/shelve") {
    const kind = parsed.query.kind === "series" ? "series" : "movies";
    const category = String(parsed.query.category || "Todas").toLowerCase();
    const year = String(parsed.query.year || "Todos");
    const page = parseInt(parsed.query.page, 10) || 1;
    const map = SHELF_IDS[kind] || SHELF_IDS.movies;
    let colId = parsed.query.columnId ? parseInt(parsed.query.columnId, 10) : 0;
    if (!colId) {
      if (year === "2026" && category === "todas") colId = map["2026"];
      else if (category !== "todas" && map[category]) colId = map[category];
      else colId = map["all"];
    }
    const rowLabel = category !== "todas" ? parsed.query.category : (year === "2026" ? "2026" : "");
    return fetchShelve(colId, page, 100, kind === "series" ? "series" : "movie", rowLabel).then((r) => {
      sendJson(res, 200, r);
    });
  }

  // API: Home catalog (featured, movies, series) enriched with real v3/getShelveData 2026 + All sorted by newest releaseDate
  if (pathname === "/api/home") {
    const root = parsed.query.root || "movies";
    const page = parseInt(parsed.query.page, 10) || 1;
    return magis.home(root, page, async (err, data) => {
      if (err) return sendJson(res, 500, { error: err.message });
      if (root === "movies" || root === "series") {
        const map = SHELF_IDS[root];
        const defKind = root === "series" ? "series" : "movie";
        const tasks = [
          fetchShelve(map["2026"], 1, 100, defKind, "2026"),
          fetchShelve(map["2026"], 2, 100, defKind, "2026"),
          fetchShelve(map["all"], 1, 100, defKind, ""),
          fetchShelve(map["all"], 2, 100, defKind, "")
        ];
        if (root === "movies" && map["2026_teatrales"]) {
          tasks.push(fetchShelve(map["2026_teatrales"], 1, 100, defKind, "2026"));
        }
        const results = await Promise.all(tasks);
        const merged = new Map();
        // Add v3/getShelveData items first so exact releaseDate (e.g. 2026-11-18) is preserved
        results.forEach(r => {
          (r.items || []).forEach(it => {
            if (it && it.id && !merged.has(it.id)) merged.set(it.id, it);
          });
        });
        (data.items || []).forEach(it => {
          if (it && it.id && !merged.has(it.id)) merged.set(it.id, it);
        });
        const sorted = Array.from(merged.values()).sort((a, b) => {
          const da = String(a.releaseDate || a.year || "");
          const db = String(b.releaseDate || b.year || "");
          return db.localeCompare(da);
        });
        return sendJson(res, 200, { root, pageNum: page, items: sorted });
      }
      sendJson(res, 200, data);
    });
  }

  // API: Search
  if (pathname === "/api/search") {
    const q = parsed.query.q || "";
    const page = parseInt(parsed.query.page, 10) || 1;
    return magis.search(q, page, (err, data) => {
      if (err) return sendJson(res, 500, { error: err.message });
      sendJson(res, 200, data);
    });
  }

  // API: Detail
  if (pathname === "/api/detail") {
    const id = parsed.query.id || "";
    return magis.detail(id, (err, data) => {
      if (err) return sendJson(res, 500, { error: err.message });
      sendJson(res, 200, data);
    });
  }

// Load Mariantv_plus direct channels for merged TV grid
let localTvPlusChannels = [];
try {
  const rawTv = JSON.parse(fs.readFileSync(path.join(__dirname, "live_channels.json"), "utf8"));
  if (Array.isArray(rawTv)) {
    localTvPlusChannels = rawTv.filter(c => c && c.id && c.streamUrl).map((c, idx) => ({
      channelCode: String(c.id),
      id: String(c.id),
      index: c.channelNumber || (101 + idx),
      number: c.channelNumber || (101 + idx),
      name: String(c.title || ("Canal " + (101 + idx))),
      title: String(c.title || ("Canal " + (101 + idx))),
      category: String(c.category || "Argentina"),
      logo: String(c.posterUrl || ""),
      poster: String(c.posterUrl || ""),
      streamUrl: String(c.streamUrl || "")
    }));
  }
} catch (_) {}

  // API: Live Categories (all Mariantv_plus categories + Marianflix Portal categories, 3.5s timeout so it NEVER hangs!)
  if (pathname === "/api/live-categories") {
    let sent = false;
    const baseMerged = [
      { id: "__ALL_MERGED__", name: "Todos (Fusión)" },
      { id: "__ARGENTINA__", name: "Argentina" },
      { id: "__LOCAL_CAT__:Deportes", name: "Deportes" },
      { id: "__LOCAL_CAT__:Cine y Series", name: "Cine y Series" },
      { id: "__LOCAL_CAT__:Noticias", name: "Noticias" },
      { id: "__LOCAL_CAT__:Infantil", name: "Infantil" },
      { id: "__LOCAL_CAT__:Entretenimiento", name: "Entretenimiento" },
      { id: "__LOCAL_CAT__:Música", name: "Música" },
      { id: "__LOCAL_CAT__:Cultura y Ciencia", name: "Cultura y Ciencia" },
      { id: "__LOCAL_CAT__:TV Abierta", name: "TV Abierta" },
      { id: "__MARIANTV__", name: "MarianTV+ (Directo)" }
    ];
    const finish = (cats) => {
      if (sent) return;
      sent = true;
      const merged = [...baseMerged];
      const seenNames = new Set(merged.map(m => m.name.toLowerCase()));
      (cats || []).forEach(c => {
        const cname = c.name === "ChannelList" ? "Portal Todos" : String(c.name || "");
        if (String(c.id) !== "76182" && !merged.some(m => String(m.id) === String(c.id))) {
          const label = seenNames.has(cname.toLowerCase()) ? `${cname} (Portal)` : cname;
          seenNames.add(label.toLowerCase());
          merged.push({ id: String(c.id), name: label });
        }
      });
      sendJson(res, 200, { categories: merged });
    };
    const t = setTimeout(() => finish([]), 3500);
    return magis.getLiveCategories((err, cats) => {
      clearTimeout(t);
      finish(cats);
    });
  }

  // API: Live Channels by Category (merged Mariantv_plus + Marianflix Portal, never hangs!)
  if (pathname === "/api/live-channels") {
    const rawCol = String(parsed.query.columnId || "__ALL_MERGED__");
    if (rawCol === "__ARGENTINA__") {
      const localArg = localTvPlusChannels.filter(c => c.category.toLowerCase() === "argentina");
      return sendJson(res, 200, { channels: localArg });
    }
    if (rawCol.startsWith("__LOCAL_CAT__:")) {
      const targetCat = rawCol.slice("__LOCAL_CAT__:".length).toLowerCase();
      return sendJson(res, 200, {
        channels: localTvPlusChannels.filter(c => c.category.toLowerCase() === targetCat)
      });
    }
    if (rawCol === "__MARIANTV__") {
      return sendJson(res, 200, { channels: localTvPlusChannels });
    }
    const colId = (rawCol === "__ALL_MERGED__" || rawCol === "76182") ? 76182 : (parseInt(rawCol, 10) || 76182);
    let sent = false;
    const finish = (chs) => {
      if (sent) return;
      sent = true;
      const portalList = Array.isArray(chs) ? chs : [];
      if (rawCol === "__ALL_MERGED__" || rawCol === "76182") {
        const out = [...localTvPlusChannels];
        const seen = new Set(out.map(c => c.channelCode));
        let nextNum = out.reduce((m, c) => Math.max(m, c.number || 100), 100) + 1;
        portalList.forEach(p => {
          const code = String(p.channelCode || p.id || "");
          if (code && !seen.has(code)) {
            seen.add(code);
            out.push(Object.assign({}, p, { index: nextNum, number: nextNum }));
            nextNum++;
          }
        });
        return sendJson(res, 200, { channels: out });
      }
      sendJson(res, 200, { channels: portalList });
    };
    const t = setTimeout(() => finish([]), 3500);
    return magis.getLiveChannels(colId, 1, 250, (err, chs) => {
      clearTimeout(t);
      finish(chs);
    });
  }

  // API: Session Status & Resilience Controls (shared by Web & Roku)
  if (pathname === "/api/session-status") {
    const st = magis.seedStatus ? magis.seedStatus() : {};
    const lastErr = (magis.session && magis.session.lastError) || "";
    const hasFatalErr = /portal100024|portal200001|aaa100027|aaa100028|socket hang up|timeout|sin semilla|rechaz/i.test(lastErr);
    const isActuallyReady = !!(magis.session && magis.session.ready && !hasFatalErr);
    return sendJson(res, 200, {
      ready: isActuallyReady,
      usesSeed: !!(magis.session && magis.session.usesSeed),
      lastError: lastErr,
      seedStatus: st,
      manualProxyUrl: magis.getManualProxy ? magis.getManualProxy() : "",
      customM3uUrl: customVodState.m3uUrl || "",
      customVodCount: (customVodState.items || []).length
    });
  }

  // API: Configure Manual HTTP Proxy (GET or POST, shared for Web & Roku)
  if (pathname === "/api/manual-proxy") {
    if (req.method === "GET") {
      const proxyUrl = String(parsed.query.proxyUrl || "").trim();
      magis.setManualProxy(proxyUrl);
      saveProxyConfig(proxyUrl);
      magis.ensureSession(() => {});
      return sendJson(res, 200, { ok: true, manualProxyUrl: proxyUrl });
    }
    if (req.method === "POST") {
      return readJsonBody(req, (err, data) => {
        if (err) return sendJson(res, 400, { error: "JSON inválido" });
        const proxyUrl = String(data.proxyUrl || "").trim();
        magis.setManualProxy(proxyUrl);
        saveProxyConfig(proxyUrl);
        magis.ensureSession(() => {});
        sendJson(res, 200, { ok: true, manualProxyUrl: proxyUrl });
      });
    }
  }

  // API: Test Manual HTTP Proxy connectivity (CONNECT / TCP latency check)
  if (pathname === "/api/test-proxy" && req.method === "POST") {
    return readJsonBody(req, (err, data) => {
      if (err) return sendJson(res, 400, { error: "JSON inválido" });
      const raw = String(data.proxyUrl || "").trim();
      if (!raw) return sendJson(res, 400, { ok: false, error: "Ingresá una URL de proxy primero" });
      let p;
      try { p = url.parse(raw.includes("://") ? raw : ("http://" + raw)); } catch (_) {
        return sendJson(res, 400, { ok: false, error: "Formato de proxy inválido" });
      }
      const pHost = p.hostname;
      const pPort = parseInt(p.port, 10) || 8080;
      const t0 = Date.now();
      let done = false;
      const finish = (ok, msg) => {
        if (done) return;
        done = true;
        sendJson(res, 200, { ok, ms: Date.now() - t0, message: msg });
      };
      const hdrs = { Host: "www.google.com:443" };
      if (p.auth) hdrs["Proxy-Authorization"] = "Basic " + Buffer.from(p.auth).toString("base64");
      const reqTest = http.request({ host: pHost, port: pPort, method: "CONNECT", path: "www.google.com:443", headers: hdrs });
      reqTest.setTimeout(6000, () => { try { reqTest.destroy(); } catch (_) {} finish(false, "Timeout (6s) — el proxy no responde"); });
      reqTest.on("error", (e) => finish(false, "Error de red: " + e.message));
      reqTest.on("connect", (pRes, sock) => {
        try { sock.destroy(); } catch (_) {}
        if (pRes.statusCode === 200) finish(true, `Proxy conectado correctamente (${Date.now() - t0} ms)`);
        else finish(false, `El proxy respondió HTTP ${pRes.statusCode}`);
      });
      reqTest.end();
    });
  }

  // API: Force Refresh Seeds now (GET or POST, bounded 8s timeout so browser never hits AbortError)
  if (pathname === "/api/refresh-seeds") {
    let sent = false;
    const finish = (err) => {
      if (sent) return;
      sent = true;
      const lastErr = (err && err.message) || (magis.session && magis.session.lastError) || "";
      const hasFatalErr = /portal100024|portal200001|aaa100027|aaa100028|socket hang up|timeout|sin semilla|rechaz/i.test(lastErr);
      const isReady = !err && !!(magis.session && magis.session.ready && !hasFatalErr);
      sendJson(res, 200, {
        ok: isReady,
        ready: isReady,
        error: lastErr,
        seedStatus: magis.seedStatus ? magis.seedStatus() : {}
      });
    };
    const timer = setTimeout(() => finish(new Error((magis.session && magis.session.lastError) || "Tiempo de espera agotado conectando al portal")), 14000);
    return magis.forceRefreshSeeds((err) => {
      clearTimeout(timer);
      finish(err);
    });
  }

  // API: Set Manual Session (user-provided sn, userId, userToken)
  if (pathname === "/api/manual-session" && req.method === "POST") {
    return readJsonBody(req, (err, data) => {
      if (err) return sendJson(res, 400, { error: "JSON inválido" });
      const ok = magis.setManualSession(data.sn, data.userId, data.userToken);
      if (!ok) return sendJson(res, 400, { error: "Completá sn, userId y userToken" });
      sendJson(res, 200, { ok: true, ready: true });
    });
  }

  // API: Custom VOD M3U Playlist (Películas / Series propias para Web y Roku)
  if (pathname === "/api/custom-vod") {
    if (req.method === "POST") {
      return readJsonBody(req, (err, data) => {
        if (err) return sendJson(res, 400, { error: "JSON inválido" });
        const m3uUrl = String(data.m3uUrl || "").trim();
        if (!m3uUrl) {
          customVodState = { m3uUrl: "", items: [] };
          saveCustomVod();
          return sendJson(res, 200, { ok: true, items: [], m3uUrl: "" });
        }
        return magis.fetchM3u(m3uUrl, (fErr, raw) => {
          if (fErr || !raw) return sendJson(res, 400, { error: (fErr && fErr.message) || "No se pudo descargar la lista M3U" });
          const parsedList = magis.parseM3u(raw) || [];
          const items = parsedList.filter(x => x && x.streamUrl).slice(0, 1500).map((x, idx) => ({
            id: "custom_" + (idx + 1),
            title: String(x.title || x.name || ("Video " + (idx + 1))),
            kind: /s\d+e\d+|temporada|episodio|serie|cap/i.test(String(x.title || x.category || "")) ? "series" : "movie",
            year: "2026",
            score: "8.5",
            genres: [String(x.category || "Lista Propia")],
            synopsis: "Título cargado desde tu lista VOD M3U propia.",
            poster: String(x.poster || x.logo || ""),
            backdrop: String(x.poster || x.logo || ""),
            streamUrl: String(x.streamUrl)
          }));
          customVodState = { m3uUrl, items };
          saveCustomVod();
          sendJson(res, 200, { ok: true, m3uUrl, count: items.length, items });
        });
      });
    }
    return sendJson(res, 200, { m3uUrl: customVodState.m3uUrl || "", items: customVodState.items || [] });
  }

  // API: Resolve VOD (Movie / Series Episode) - supports Custom VOD M3U + Portal TS/HLS
  if (pathname === "/api/resolve-vod") {
    const id = parsed.query.id || "";
    const seriesId = parsed.query.seriesId || "";
    if (String(id).startsWith("custom_")) {
      const found = (customVodState.items || []).find(x => x.id === id);
      if (!found) return sendJson(res, 404, { error: "Título no encontrado en tu lista propia" });
      const u = found.streamUrl;
      const isHls = /\.m3u8(\?|$)/i.test(u);
      const isMp4 = /\.(mp4|webm|mkv)(\?|$)/i.test(u);
      return sendJson(res, 200, {
        title: found.title,
        format: isHls ? "hls" : (isMp4 ? "mp4" : "ts"),
        hlsUrl: isHls ? `/api/proxy?url=${encodeURIComponent(u)}` : "",
        streamUrl: `/api/proxy?url=${encodeURIComponent(u)}`,
        duration: 0,
        audioTracks: [{ index: 0, lang: "es" }],
        subtitles: []
      });
    }
    const qualityPref = String(parsed.query.quality || "auto").trim().toLowerCase();
    const trackIdxRaw = parsed.query.trackIndex !== undefined ? parseInt(parsed.query.trackIndex, 10) : -1;
    const wantsHighRes = qualityPref === "2160" || qualityPref === "4k" || qualityPref === "1440" || qualityPref === "2k";
    const resolveOpts = { hevc: wantsHighRes, uhd: wantsHighRes, quality: qualityPref };
    if (!Number.isNaN(trackIdxRaw) && trackIdxRaw >= 0) resolveOpts.trackIndex = trackIdxRaw;
    return magis.resolve(id, seriesId, resolveOpts, async (err, pb) => {
      if (err) return sendJson(res, 500, { error: err.message });
      const ext = pb.url.toLowerCase().endsWith(".mp4") ? "mp4" : "ts";
      const tsInfo = ext === "ts" ? await probeTsInfo(pb.url, pb.headers) : { totalLen: 0, audioPids: [] };
      const durationSec = Number(pb.duration) > 30 ? Number(pb.duration) : 5400;
      const token = registerStream(pb.url, pb.headers, false, {
        totalLen: tsInfo.totalLen,
        audioPids: tsInfo.audioPids,
        patPacket: tsInfo.patPacket,
        pmtPacket: tsInfo.pmtPacket,
        durationSec
      });
      const subs = (pb.subtitles || []).map((s) => ({
        lang: s.lang,
        url: "/api/sub?url=" + encodeURIComponent(s.url),
        format: s.format || "srt"
      }));
      const rawLangs = String(pb.audio || "").split(/[,;/|]/).map(s => s.trim()).filter(Boolean);
      const trackCount = Math.max(rawLangs.length, tsInfo.audioPids.length, 1);
      const audioTracks = [];
      for (let i = 0; i < trackCount; i++) {
        audioTracks.push({
          index: i,
          lang: rawLangs[i] || (i === 0 ? "es" : "en"),
          pid: tsInfo.audioPids[i] || 0
        });
      }
      sendJson(res, 200, {
        streamUrl: `/api/stream/${token}.${ext}`,
        hlsUrl: (ext === "ts" && tsInfo.totalLen > 188000) ? `/api/vod-hls/${token}/index.m3u8` : "",
        format: ext,
        mime: pb.mime,
        codec: pb.codec,
        quality: pb.quality,
        selectedTrack: pb.selectedTrack || null,
        trackIndex: pb.trackIndex || 0,
        duration: durationSec,
        audio: pb.audio,
        audioTracks,
        availableTracks: pb.availableTracks || [],
        subtitles: subs,
        name: pb.name
      });
    });
  }

  // API: Resolve Live TV Channel
  if (pathname === "/api/resolve-live") {
    const code = parsed.query.code || "";
    return magis.resolveLive(code, (err, pb) => {
      if (err) return sendJson(res, 500, { error: err.message });
      const token = registerStream(pb.url, pb.headers, true);
      sendJson(res, 200, {
        streamUrl: `/api/hls/${token}/index.m3u8`,
        format: "m3u8",
        name: pb.name
      });
    });
  }

  // API: Proxy Subtitle SRT
  if (pathname === "/api/sub") {
    const subUrl = parsed.query.url || "";
    if (!subUrl) {
      res.writeHead(400);
      return res.end("Missing subtitle url");
    }
    return proxyRequest(
      subUrl,
      { "User-Agent": "Ranger/4.9.4-17294ac0" },
      req,
      res,
      (status, headers, rawText) => {
        res.writeHead(status, {
          "Content-Type": "text/plain; charset=utf-8",
          "Access-Control-Allow-Origin": "*"
        });
        res.end(rawText);
      }
    );
  }

  // API: Virtual VOD HLS for instant seeking (-10s/+10s/timeline) & independent Audio PID switching
  if (pathname.startsWith("/api/vod-hls/")) {
    const parts = pathname.slice("/api/vod-hls/".length).split("/");
    const token = parts[0];
    const subPath = parts.slice(1).join("/");
    const entry = streamTokens.get(token);
    if (!entry || !entry.totalLen) {
      res.writeHead(404);
      return res.end("VOD HLS token expired");
    }
    const audioIdx = parseInt(parsed.query.audio, 10) || 0;

    if (subPath === "index.m3u8") {
      const segDur = 8;
      const totalDur = Math.max(60, entry.durationSec || 5400);
      const segCount = Math.max(1, Math.ceil(totalDur / segDur));
      const totalPackets = Math.floor(entry.totalLen / 188);
      const pktsPerSeg = Math.max(100, Math.floor(totalPackets / segCount));
      const lines = [
        "#EXTM3U",
        "#EXT-X-VERSION:3",
        "#EXT-X-PLAYLIST-TYPE:VOD",
        "#EXT-X-TARGETDURATION:" + (segDur + 2),
        "#EXT-X-MEDIA-SEQUENCE:0"
      ];
      let pktCursor = 0;
      for (let i = 0; i < segCount && pktCursor < totalPackets; i++) {
        const nextPkt = (i === segCount - 1) ? totalPackets : Math.min(totalPackets, pktCursor + pktsPerSeg);
        const startByte = pktCursor * 188;
        const endByte = (nextPkt * 188) - 1;
        const dur = (i === segCount - 1)
          ? Math.max(1, totalDur - (i * segDur))
          : segDur;
        lines.push(`#EXTINF:${dur.toFixed(3)},`);
        lines.push(`/api/vod-hls/${token}/seg_${startByte}_${endByte}.ts?audio=${audioIdx}`);
        pktCursor = nextPkt;
      }
      lines.push("#EXT-X-ENDLIST");
      const m3u8 = lines.join("\n") + "\n";
      res.writeHead(200, {
        "Content-Type": "application/vnd.apple.mpegurl",
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "no-store"
      });
      return res.end(m3u8);
    }

    const m = /^seg_(\d+)_(\d+)\.ts$/.exec(subPath);
    if (m) {
      const startByte = parseInt(m[1], 10);
      const endByte = parseInt(m[2], 10);
      return fetchRangeBuffer(entry.url, entry.headers, startByte, endByte)
        .then(({ buf }) => {
          // Ensure PAT + PMT are at the start of every seek segment so hls.js decodes immediately on seek
          let outBuf = buf;
          if (startByte > 0 && entry.patPacket && entry.pmtPacket) {
            outBuf = Buffer.concat([entry.patPacket, entry.pmtPacket, buf]);
          }
          if (audioIdx > 0 && entry.audioPids && entry.audioPids.length > audioIdx) {
            swapTsPids(outBuf, entry.audioPids[0], entry.audioPids[audioIdx]);
          }
          res.writeHead(200, {
            "Content-Type": "video/mp2t",
            "Content-Length": outBuf.length,
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "no-store"
          });
          res.end(outBuf);
        })
        .catch((err) => {
          if (!res.headersSent) {
            res.writeHead(502);
            res.end("Segment error: " + err.message);
          }
        });
    }
  }

  // API: Stream VOD (.ts / .mp4)
  if (pathname.startsWith("/api/stream/")) {
    const filePart = pathname.slice("/api/stream/".length);
    const token = filePart.split(".")[0];
    const entry = streamTokens.get(token);
    if (!entry) {
      res.writeHead(404);
      return res.end("Stream token expired");
    }
    return proxyRequest(entry.url, entry.headers, req, res, null);
  }

  // API: Stream Live HLS (.m3u8 and segments)
  if (pathname.startsWith("/api/hls/")) {
    const parts = pathname.slice("/api/hls/".length).split("/");
    const token = parts[0];
    const subPath = parts.slice(1).join("/");
    const entry = streamTokens.get(token);
    if (!entry) {
      res.writeHead(404);
      return res.end("HLS token expired");
    }

    if (subPath === "index.m3u8" || subPath.startsWith("child_")) {
      const targetUrl =
        subPath === "index.m3u8"
          ? entry.url
          : Buffer.from(subPath.slice("child_".length), "base64url").toString("utf8");

      return proxyRequest(targetUrl, entry.headers, req, res, (status, headers, rawManifest) => {
        const lines = String(rawManifest || "").split(/\r?\n/);
        const rewritten = lines
          .map((line) => {
            const trimmed = line.trim();
            if (!trimmed) return line;
            if (!trimmed.startsWith("#")) {
              const abs = url.resolve(targetUrl, trimmed);
              const b64 = Buffer.from(abs, "utf8").toString("base64url");
              if (abs.includes(".m3u8")) {
                return `/api/hls/${token}/child_${b64}`;
              }
              return `/api/hls/${token}/seg_${b64}.ts`;
            }
            return line;
          })
          .join("\n");

        res.writeHead(200, {
          "Content-Type": "application/vnd.apple.mpegurl",
          "Access-Control-Allow-Origin": "*",
          "Cache-Control": "no-store"
        });
        res.end(rewritten);
      });
    }

    if (subPath.startsWith("seg_")) {
      const b64 = subPath.slice("seg_".length).replace(/\.ts$/i, "");
      const segUrl = Buffer.from(b64, "base64url").toString("utf8");
      return proxyRequest(segUrl, entry.headers, req, res, null);
    }
  }

  // Static files
  let staticFile = pathname === "/" ? "index.html" : pathname.slice(1);
  const fullPath = path.join(__dirname, staticFile);
  if (fullPath.startsWith(__dirname) && fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
    const ext = path.extname(fullPath).toLowerCase();
    const mimeMap = {
      ".html": "text/html; charset=utf-8",
      ".js": "application/javascript; charset=utf-8",
      ".json": "application/json; charset=utf-8",
      ".css": "text/css; charset=utf-8",
      ".png": "image/png",
      ".svg": "image/svg+xml"
    };
    res.writeHead(200, {
      "Content-Type": mimeMap[ext] || "application/octet-stream",
      "Access-Control-Allow-Origin": "*"
    });
    return fs.createReadStream(fullPath).pipe(res);
  }

  res.writeHead(404);
  res.end("Not found");
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`====================================================`);
  console.log(`  MARIANFLIX WEB ACTIVO EN: http://localhost:${PORT}`);
  console.log(`====================================================`);
  // Auto-activate portal session on boot (uses direct v8/active on Render/US, or seeds/manual proxy)
  setTimeout(() => {
    try {
      magis.ensureSession((err, sess) => {
        if (err) console.log("[boot] sesión inicial pendiente:", err.message);
        else console.log("[boot] sesión VOD activada automáticamente (sn=" + String((sess && sess.sn) || "").slice(0, 12) + ")");
      });
    } catch (_) {}
  }, 500);
});
