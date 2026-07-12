/**
 * depfirewall license verifier — Cloudflare Worker + KV.
 *
 * GET /verify?key=K&repo=owner/name
 *   → {valid: true, plan, repo}       key exists; binds to repo on first use
 *   → {valid: false, reason}          unknown key, or key bound to a different repo
 *
 * KV namespace: LICENSES. Value schema: {"plan":"pro","repo":null|"owner/name","issued":"ISO"}
 * Issue a key:  wrangler kv key put --binding=LICENSES "dfw_<random>" '{"plan":"pro","repo":null,"issued":"2026-07-12"}'
 * Revoke:       wrangler kv key delete --binding=LICENSES "dfw_<key>"
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== "/verify") {
      return json({ error: "not found" }, 404);
    }
    const key = url.searchParams.get("key") || "";
    const repo = (url.searchParams.get("repo") || "").toLowerCase();
    if (!key || !repo) {
      return json({ valid: false, reason: "missing key or repo" }, 400);
    }

    const raw = await env.LICENSES.get(key);
    if (!raw) {
      return json({ valid: false, reason: "unknown license key" });
    }

    let lic;
    try { lic = JSON.parse(raw); } catch { lic = {}; }

    if (!lic.repo) {
      // First use: bind the key to this repo to prevent key sharing.
      lic.repo = repo;
      lic.bound = new Date().toISOString();
      await env.LICENSES.put(key, JSON.stringify(lic));
      return json({ valid: true, plan: lic.plan || "pro", repo });
    }
    if (lic.repo === repo) {
      return json({ valid: true, plan: lic.plan || "pro", repo });
    }
    return json({ valid: false, reason: `key is bound to a different repository` });
  },
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}
