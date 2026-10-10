import { getStore } from "@netlify/blobs";
import { createHash, randomInt, timingSafeEqual } from "node:crypto";

const SEED = ["652d4497c44d1d4ff98e43a34c21b3209be64c7dade955ef6cf7d2010cb58356", "efbb61db394a5aecc01c52ce212348a742bca79156ce5026b72131323915b9f4", "d85d49df71709d5b6dd209e6a6f5d5ea9655b2a38eb84db3cdd9575904ea6d3f", "b8c2ed4792d8531d976e2f0506d5aedc08acc7f33b1bd93dfe43b9a37dcc4d2c", "8e4dae87041a88b23eb6bc59e7b8d6fb331fb55b8f7667028330649f8180fb50", "dc8361a797341a7fbb300555167ef0acb2ab57f22585d7e04b651bf3e618b87d", "0c622c5ac1c9a993c91d7486a91c9020e98c5fe46077804f9c09831e48365631", "576890ea4dbd194efa4cad7862f2e60ba2aab70470ea1aa15624b8517335cef8", "4b6266942d37e96479378316ce4a78db6a710c0af1fab4a3b3dd7dd53084d95d", "7b39d0e6e1396a66455d6e2a28d7be8c0b2b7f21381585b22602506d244926dd"];
const sha = (s) => createHash("sha256").update("lc:" + s).digest("hex");
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const AL = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const mk = () => "LC-" + [0, 1, 2].map(() => Array.from({ length: 4 }, () => AL[randomInt(AL.length)]).join("")).join("-");
const nid = (n) => "Key-" + String(n).padStart(2, "0");

export default async (req) => {
  if (req.method !== "POST") return J({ ok: false, msg: "Method" }, 405);
  const b = await req.json().catch(() => ({}));
  const meta = getStore({ name: "meta", consistency: "strong" });
  const claims = getStore({ name: "claims", consistency: "strong" });
  let keys = await meta.get("keys", { type: "json" });
  if (!keys) {
    keys = SEED.map((h, i) => ({ id: nid(i + 1), label: "", h }));
    await meta.setJSON("keys", keys);
  }

  if (b.action === "admin") {
    const s = process.env.ADMIN_SECRET || "";
    const a = Buffer.from(String(b.admin || "")), c = Buffer.from(s);
    if (!s || a.length !== c.length || !timingSafeEqual(a, c)) return J({ ok: false, msg: "Admin secret thik nai" }, 401);
    let made = null;
    if (b.op === "create") {
      const key = mk(), id = nid(keys.length + 1);
      keys.push({ id, label: String(b.label || "").slice(0, 40), h: sha(key) });
      await meta.setJSON("keys", keys);
      made = { id, key };
    }
    const k = keys.find((x) => x.id === b.id);
    if (b.op === "reset" && k) await claims.delete(k.h);
    if (b.op === "block" && k) await claims.setJSON(k.h, { blocked: true, at: Date.now() });
    const list = [];
    for (const x of keys) {
      const c2 = await claims.get(x.h, { type: "json" });
      list.push({ id: x.id, label: x.label, state: !c2 ? "free" : c2.blocked ? "blocked" : "used", at: c2 ? c2.at : null });
    }
    return J({ ok: true, list, made });
  }

  const key = String(b.key || "").trim().toUpperCase();
  const dev = String(b.device || "").slice(0, 80);
  if (!key || dev.length < 8) return J({ ok: false, msg: "Key likhun" }, 400);
  const h = sha(key);
  if (!keys.some((x) => x.h === h)) return J({ ok: false, msg: "Key thik nai" }, 401);
  let c = await claims.get(h, { type: "json" });
  if (!c) {
    await claims.setJSON(h, { device: dev, at: Date.now() });
    c = await claims.get(h, { type: "json" });
  }
  if (c.blocked) return J({ ok: false, msg: "Ei key bondho kora hoyeche" }, 403);
  if (c.device !== dev) return J({ ok: false, msg: "Ei key onno device-e use hoye gese" }, 403);
  return J({ ok: true });
};

export const config = { path: "/api/auth" };
