import worker from './worker.js';

const store = new Map([["dfw_valid1", JSON.stringify({plan: "pro", repo: null, issued: "2026-07-12"})]]);
const env = { LICENSES: {
  get: async k => store.get(k) ?? null,
  put: async (k, v) => { store.set(k, v); },
}};
const call = async (path) => {
  const res = await worker.fetch(new Request("https://x.dev" + path), env);
  return { status: res.status, body: await res.json() };
};

const assert = (cond, msg) => { if (!cond) { console.error("FAIL:", msg); process.exit(1); } console.log("ok:", msg); };

let r = await call("/verify?key=unknown&repo=acme/app");
assert(r.body.valid === false && r.body.reason.includes("unknown"), "unknown key rejected");

r = await call("/verify?key=dfw_valid1&repo=acme/app");
assert(r.body.valid === true && r.body.repo === "acme/app", "valid key accepted + bound on first use");

r = await call("/verify?key=dfw_valid1&repo=acme/app");
assert(r.body.valid === true, "same repo still valid after binding");

r = await call("/verify?key=dfw_valid1&repo=evil/other");
assert(r.body.valid === false && r.body.reason.includes("bound"), "key sharing across repos rejected");

r = await call("/verify?key=&repo=");
assert(r.status === 400, "missing params -> 400");

r = await call("/nope");
assert(r.status === 404, "unknown path -> 404");

console.log("WORKER LOGIC: ALL PASS");
