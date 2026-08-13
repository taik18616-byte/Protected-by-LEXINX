const express = require("express");
const crypto = require("crypto");

const app = express();

app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use(express.json({ limit: "1kb", strict: true }));

const PORT = process.env.PORT || 3000;

const TOKEN = process.env.LEXINX_TOKEN;
const VERSION = "V50";

if (!TOKEN) {
throw new Error("LEXINX_TOKEN is missing");
}

const WINDOW = 60_000;
const MAX_REQUESTS = 10;
const MAX_FAILURES = 3;
const LOCK_TIME = 10 * 60_000;
const CLOCK_SKEW = 30;
const NONCE_TTL = 120_000;

const clients = new Map();
const nonces = new Map();

function reject(res) {
return res
.status(403)
.type("text")
.send("Blocked by LEXINX v50 protection");
}

function getIP(req) {
return (
req.headers["cf-connecting-ip"] ||
req.headers["x-real-ip"] ||
req.ip ||
req.socket.remoteAddress ||
"unknown"
);
}

function state(ip) {
if (!clients.has(ip)) {
clients.set(ip, {
window: Date.now(),
requests: 0,
failures: 0,
lockedUntil: 0
});
}

return clients.get(ip);

}

function allowed(req) {
const s = state(getIP(req));
const t = Date.now();

if (s.lockedUntil > t) {  
    return false;  
}  

if (t - s.window > WINDOW) {  
    s.window = t;  
    s.requests = 0;  
}  

s.requests++;  

if (s.requests > MAX_REQUESTS) {  
    s.lockedUntil = t + LOCK_TIME;  
    return false;  
}  

return true;

}

function fail(req) {
const s = state(getIP(req));

s.failures++;  

if (s.failures >= MAX_FAILURES) {  
    s.lockedUntil =  
        Date.now() + LOCK_TIME;  
}

}

function validToken(value) {
if (typeof value !== "string") {
return false;
}

const a = Buffer.from(TOKEN);  
const b = Buffer.from(value);  

return (  
    a.length === b.length &&  
    crypto.timingSafeEqual(a, b)  
);

}

function cleanup() {
const t = Date.now();

for (const [nonce, created] of nonces) {  
    if (t - created > NONCE_TTL) {  
        nonces.delete(nonce);  
    }  
}  

for (const [ip, s] of clients) {  
    if (  
        t - s.window > 600_000 &&  
        s.lockedUntil < t  
    ) {  
        clients.delete(ip);  
    }  
}

}

setInterval(cleanup, 30_000);

// ===============================
// HOME
// ===============================

app.get("/", (req, res) => {
res.type("text").send("cc");
});

// ===============================
// BLOCK DIRECT GET
// ===============================

app.get("/api/sound", (req, res) => {
reject(res);
});

app.head("/api/sound", (req, res) => {
reject(res);
});

// ===============================
// AUTH API
// ===============================

app.post("/api/sound", (req, res) => {

if (!allowed(req)) {  
    return reject(res);  
}  

const contentType =  
    req.headers["content-type"] || "";  

if (  
    !contentType  
        .toLowerCase()  
        .startsWith("application/json")  
) {  
    fail(req);  
    return reject(res);  
}  

const token =  
    req.header("X-Token");  

const time =  
    req.header("X-Time");  

const nonce =  
    req.header("X-Nonce");  

const version =  
    req.header("X-Version");  

if (  
    !token ||  
    !time ||  
    !nonce ||  
    !version  
) {  
    fail(req);  
    return reject(res);  
}  

if (!validToken(token)) {  
    fail(req);  
    return reject(res);  
}  

if (version !== VERSION) {  
    fail(req);  
    return reject(res);  
}  

if (!/^\d{10}$/.test(time)) {  
    fail(req);  
    return reject(res);  
}  

const timestamp = Number(time);  

if (  
    Math.abs(  
        Math.floor(Date.now() / 1000) -  
        timestamp  
    ) > CLOCK_SKEW  
) {  
    fail(req);  
    return reject(res);  
}  

if (!/^[A-Za-z0-9]{32}$/.test(nonce)) {  
    fail(req);  
    return reject(res);  
}  

if (nonces.has(nonce)) {  
    fail(req);  
    return reject(res);  
}  

nonces.set(nonce, Date.now());  

if (  
    !req.body ||  
    typeof req.body !== "object" ||  
    Array.isArray(req.body) ||  
    Object.keys(req.body).length !== 0  
) {  
    fail(req);  
    return reject(res);  
}  

// ===========================  
// AUTHORIZED  
// ===========================  

const session =  
    crypto.randomBytes(24).toString("hex");  

return res.json({  
    ok: true,  
    version: VERSION,  
    session,  
    expires: 30,  

    // Chỉ trả dữ liệu cần thiết.  
    soundId: 132545213997354,  
    volume: 4,  
    speed: 0.2  
});

});

// ===============================
// UNKNOWN ROUTES
// ===============================

app.use((req, res) => {
reject(res);
});

app.listen(PORT, () => {
console.log(
[LEXINX V50] Online :${PORT}
);
});
