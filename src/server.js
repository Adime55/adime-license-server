import crypto from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import http from "node:http";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8787);
const ADMIN_TOKEN = String(process.env.ADMIN_TOKEN || "").trim();
const DATA_DIR = process.env.DATA_DIR || join(__dirname, "..", "data");
const DATA_FILE = process.env.LICENSE_DATA_FILE || join(DATA_DIR, "licenses.json");

function cleanString(value) {
  return String(value ?? "").trim();
}

function now() {
  return new Date().toISOString();
}

function json(response, status, payload) {
  response.writeHead(status, {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,PATCH,OPTIONS",
    "access-control-allow-headers": "authorization,content-type",
    "content-type": "application/json; charset=utf-8"
  });
  response.end(JSON.stringify(payload));
}

function parseFeatures(value) {
  if (Array.isArray(value)) {
    return value.map((item) => cleanString(item)).filter(Boolean);
  }
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed.map((item) => cleanString(item)).filter(Boolean) : [];
    } catch {
      return value
        .split(",")
        .map((item) => cleanString(item))
        .filter(Boolean);
    }
  }
  return [];
}

function isExpired(expiresAt) {
  const time = Date.parse(cleanString(expiresAt));
  return Number.isFinite(time) && Date.now() > time;
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (!raw) {
    return {};
  }
  try {
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

function normalizeLicense(item = {}, licenseKey = "") {
  const timestamp = now();
  return {
    licenseKey: cleanString(item.licenseKey || item.license_key || licenseKey),
    note: cleanString(item.note || ""),
    active: item.active !== false && item.active !== 0,
    maxDevices: Math.max(1, Number(item.maxDevices || item.max_devices || 1)),
    expiresAt: cleanString(item.expiresAt || item.expires_at || ""),
    allowedFeatures: parseFeatures(item.allowedFeatures || item.allowed_features).length
      ? parseFeatures(item.allowedFeatures || item.allowed_features)
      : ["all"],
    devices: Array.isArray(item.devices) ? item.devices.filter((device) => device && typeof device === "object") : [],
    createdAt: cleanString(item.createdAt || item.created_at || timestamp),
    updatedAt: cleanString(item.updatedAt || item.updated_at || timestamp)
  };
}

async function readStore() {
  await mkdir(DATA_DIR, { recursive: true });
  try {
    const parsed = JSON.parse(await readFile(DATA_FILE, "utf8"));
    const source = parsed && typeof parsed === "object" ? parsed : {};
    const licenses = source.licenses && typeof source.licenses === "object" ? source.licenses : source;
    const normalized = {};
    for (const [key, value] of Object.entries(licenses)) {
      const item = normalizeLicense(value, key);
      if (item.licenseKey) {
        normalized[item.licenseKey] = item;
      }
    }
    return { licenses: normalized };
  } catch {
    const seeded = seedLicenses();
    await writeStore(seeded);
    return seeded;
  }
}

async function writeStore(store) {
  await mkdir(DATA_DIR, { recursive: true });
  const tempFile = `${DATA_FILE}.${process.pid}.tmp`;
  await writeFile(tempFile, JSON.stringify(store, null, 2), "utf8");
  await rename(tempFile, DATA_FILE);
}

function seedLicenses() {
  const timestamp = now();
  const seeded = {
    "ADIME-TEST-001": normalizeLicense(
      {
        note: "旧测试授权",
        active: true,
        maxDevices: 1,
        expiresAt: "2026-12-31T23:59:59.000Z",
        allowedFeatures: ["all"],
        createdAt: timestamp,
        updatedAt: timestamp
      },
      "ADIME-TEST-001"
    )
  };
  const raw = cleanString(process.env.SEED_LICENSES_JSON);
  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      for (const [key, value] of Object.entries(parsed)) {
        const item = normalizeLicense(value, key);
        if (item.licenseKey) {
          seeded[item.licenseKey] = item;
        }
      }
    } catch {
      // Ignore invalid seed JSON so the service can still boot.
    }
  }
  return { licenses: seeded };
}

function requireAdmin(request) {
  const received = cleanString(request.headers.authorization).replace(/^Bearer\s+/i, "");
  return Boolean(ADMIN_TOKEN && received && received === ADMIN_TOKEN);
}

function publicLicense(item) {
  return {
    licenseKey: item.licenseKey,
    note: item.note,
    active: item.active,
    maxDevices: item.maxDevices,
    deviceCount: item.devices.length,
    expiresAt: item.expiresAt,
    allowedFeatures: item.allowedFeatures,
    createdAt: item.createdAt,
    updatedAt: item.updatedAt
  };
}

async function handleValidate(request, response) {
  const body = await readBody(request);
  const licenseKey = cleanString(body.licenseKey);
  const deviceId = cleanString(body.deviceId);
  if (!licenseKey || !deviceId) {
    return json(response, 200, { active: false, status: "missing_fields", message: "缺少授权码或设备 ID" });
  }

  const store = await readStore();
  const license = store.licenses[licenseKey];
  if (!license || !license.active) {
    return json(response, 200, { active: false, status: "inactive", message: "授权码不存在或已停用" });
  }
  if (isExpired(license.expiresAt)) {
    return json(response, 200, { active: false, status: "expired", message: "授权码已过期", expiresAt: license.expiresAt });
  }

  const timestamp = now();
  const existing = license.devices.find((device) => device.deviceId === deviceId);
  if (!existing && license.devices.length >= license.maxDevices) {
    return json(response, 200, {
      active: false,
      status: "device_limit",
      message: "授权设备数量已满",
      maxDevices: license.maxDevices,
      deviceCount: license.devices.length
    });
  }

  if (existing) {
    existing.appVersion = cleanString(body.appVersion);
    existing.platform = cleanString(body.platform);
    existing.arch = cleanString(body.arch);
    existing.lastSeenAt = timestamp;
  } else {
    license.devices.push({
      id: crypto.randomUUID(),
      deviceId,
      appVersion: cleanString(body.appVersion),
      platform: cleanString(body.platform),
      arch: cleanString(body.arch),
      firstSeenAt: timestamp,
      lastSeenAt: timestamp
    });
  }
  license.updatedAt = timestamp;
  await writeStore(store);

  return json(response, 200, {
    active: true,
    status: "active",
    message: "授权有效",
    expiresAt: license.expiresAt,
    allowedFeatures: license.allowedFeatures
  });
}

async function handleList(response) {
  const store = await readStore();
  const items = Object.values(store.licenses)
    .map(publicLicense)
    .sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
  return json(response, 200, { items });
}

async function handleCreate(request, response) {
  const body = await readBody(request);
  const timestamp = now();
  const licenseKey = cleanString(body.licenseKey) || `ADIME-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;
  const item = normalizeLicense(
    {
      ...body,
      licenseKey,
      createdAt: timestamp,
      updatedAt: timestamp,
      devices: []
    },
    licenseKey
  );
  const store = await readStore();
  store.licenses[item.licenseKey] = item;
  await writeStore(store);
  return json(response, 200, { item: publicLicense(item) });
}

async function handleUpdate(request, response, licenseKey) {
  const body = await readBody(request);
  const store = await readStore();
  const current = store.licenses[licenseKey];
  if (!current) {
    return json(response, 404, { error: "not_found", message: "授权码不存在" });
  }
  if (Object.hasOwn(body, "note")) {
    current.note = cleanString(body.note);
  }
  if (Object.hasOwn(body, "active")) {
    current.active = body.active === true || body.active === 1;
  }
  if (Object.hasOwn(body, "maxDevices")) {
    current.maxDevices = Math.max(1, Number(body.maxDevices || 1));
  }
  if (Object.hasOwn(body, "expiresAt")) {
    current.expiresAt = cleanString(body.expiresAt);
  }
  if (Object.hasOwn(body, "allowedFeatures")) {
    current.allowedFeatures = parseFeatures(body.allowedFeatures);
  }
  current.updatedAt = now();
  await writeStore(store);
  return json(response, 200, { item: publicLicense(current) });
}

export function createLicenseServer() {
  return http.createServer(async (request, response) => {
    try {
      const url = new URL(request.url || "/", `http://${request.headers.host || "127.0.0.1"}`);
      if (request.method === "OPTIONS") {
        return json(response, 200, {});
      }
      if (url.pathname === "/health") {
        return json(response, 200, { ok: true, service: "adime-license-server" });
      }
      if (url.pathname === "/validate" && request.method === "POST") {
        return handleValidate(request, response);
      }
      if (url.pathname === "/admin/licenses") {
        if (!requireAdmin(request)) {
          return json(response, 401, { error: "unauthorized" });
        }
        if (request.method === "GET") {
          return handleList(response);
        }
        if (request.method === "POST") {
          return handleCreate(request, response);
        }
      }
      const match = url.pathname.match(/^\/admin\/licenses\/([^/]+)$/);
      if (match && request.method === "PATCH") {
        if (!requireAdmin(request)) {
          return json(response, 401, { error: "unauthorized" });
        }
        return handleUpdate(request, response, decodeURIComponent(match[1]));
      }
      return json(response, 404, { error: "not_found" });
    } catch (error) {
      return json(response, 500, { error: "server_error", message: error instanceof Error ? error.message : String(error) });
    }
  });
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const server = createLicenseServer();
  server.listen(PORT, () => {
    console.log(`Adime license server listening on ${PORT}`);
  });
}
