"use strict";

const express = require("express");
const crypto = require("crypto");

const app = express();

app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use(express.json({
limit: "1kb",
strict: true
}));

// ============================================================
// CONFIG
// ============================================================

const PORT = process.env.PORT || 3000;
const SERVER_SECRET = process.env.LEXINX_SECRET;

if (!SERVER_SECRET || SERVER_SECRET.length < 32) {
throw new Error(
"LEXINX_SECRET must be at least 32 characters"
);
}

const VERSION = "V50";

const NONCE_TTL = 60_000;
const SESSION_TTL = 30_000;

const RATE_WINDOW = 60_000;
const MAX_REQUESTS = 20;
const MAX_FAILURES = 5;
const LOCK_TIME = 300_000;

// ============================================================
// MEMORY
// ============================================================

const nonces = new Map();
const sessions = new Map();
const clients = new Map();

// ============================================================
// HELPERS
// ============================================================

function now() {
return Date.now();
}

function unix() {
return Math.floor(now() / 1000);
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

function blocked(res) {
return res
.status(403)
.type("text/plain")
.send("Blocked by LEXINX v50 protection");
}

function clientState(ip) {
let state = clients.get(ip);

if (!state) {  
    state = {  
        window: now(),  
        requests: 0,  
        failures: 0,  
        lockedUntil: 0  
    };  

    clients.set(ip, state);  
}  

return state;

}

// ============================================================
// RATE LIMIT
// ============================================================

function checkRate(req) {
const state = clientState(getIP(req));

if (state.lockedUntil > now()) {  
    return false;  
}  

if (now() - state.window > RATE_WINDOW) {  
    state.window = now();  
    state.requests = 0;  
}  

state.requests++;  

if (state.requests > MAX_REQUESTS) {  
    state.lockedUntil =  
        now() + LOCK_TIME;  

    return false;  
}  

return true;

}

// ============================================================
// FAILURE
// ============================================================

function failure(req) {
const state = clientState(getIP(req));

state.failures++;  

if (state.failures >= MAX_FAILURES) {  
    state.lockedUntil =  
        now() + LOCK_TIME;  
}

}

// ============================================================
// NONCE
// ============================================================

function validNonce(nonce) {
return (
typeof nonce === "string" &&
/^[A-Za-z0-9]{32}$/.test(nonce)
);
}

// ============================================================
// TIMESTAMP
// ============================================================

function validTimestamp(value) {
if (
typeof value !== "string" ||
!/^\d{10}$/.test(value)
) {
return false;
}

const timestamp = Number(value);  

if (!Number.isSafeInteger(timestamp)) {  
    return false;  
}  

return (  
    Math.abs(unix() - timestamp) <= 30  
);

}

// ============================================================
// SESSION
// ============================================================

function createSession(ip) {

const session =  
    crypto  
        .randomBytes(32)  
        .toString("hex");  

sessions.set(session, {  
    ip,  
    created: now(),  
    expires: now() + SESSION_TTL,  
    version: VERSION  
});  

return session;

}

// ============================================================
// HOME
// ============================================================

app.get("/", (req, res) => {
res
.type("text/plain")
.send("cc");
});

// ============================================================
// PUBLIC LOADER
// ============================================================

app.get(
"/api/66667777",
(req, res) => {

/*  
     * Đây KHÔNG phải payload thật.  
     * Chỉ là bootstrap tối thiểu.  
     */  

    const loader = `

local HttpService = game:GetService("HttpService")

local API =
"https://l3xinx-api.onrender.com/api/sound"

local VERSION = "V50"

local function nonce()

local chars =  
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"  

local result = {}  

for i = 1, 32 do  

    local n =  
        math.random(  
            1,  
            #chars  
        )  

    result[i] =  
        chars:sub(  
            n,  
            n  
        )  
end  

return table.concat(result)

end

local response

local ok = pcall(function()

response = request({  

    Url = API,  

    Method = "POST",  

    Headers = {  

        ["Content-Type"] =  
            "application/json",  

        ["X-Time"] =  
            tostring(os.time()),  

        ["X-Nonce"] =  
            nonce(),  

        ["X-Version"] =  
            VERSION  
    },  

    Body = "{}"  
})

end)

if not ok or
not response or
response.StatusCode ~= 200 then

warn("[LEXINX] BLOCK")  
return

end

local decoded, data =
pcall(function()

return HttpService:JSONDecode(  
        response.Body  
    )  

end)

if not decoded or
type(data) ~= "table" or
data.ok ~= true then

warn("[LEXINX] AUTH FAILED")  
return

end

if data.version ~= VERSION then

warn("[LEXINX] VERSION FAILED")  
return

end

print("[LEXINX] Authorized")

-- Chỉ nhận dữ liệu cần thiết.
print("Sound:", data.config.soundId)
`;

res  
        .status(200)  
        .type("text/plain")  
        .send(loader);  
}

);

// ============================================================
// BLOCK DIRECT GET
// ============================================================

app.get(
"/api/session",
(req, res) => blocked(res)
);

// ============================================================
// SESSION AUTH
// ============================================================

app.post(
"/api/session",
(req, res) => {

// Rate limit  
    if (!checkRate(req)) {  
        return blocked(res);  
    }  

    // Content-Type  
    const contentType =  
        req.headers["content-type"] || "";  

    if (  
        !contentType  
            .toLowerCase()  
            .startsWith("application/json")  
    ) {  
        failure(req);  
        return blocked(res);  
    }  

    // Headers  
    const timestamp =  
        req.header("X-Time");  

    const nonce =  
        req.header("X-Nonce");  

    const version =  
        req.header("X-Version");  

    if (  
        !timestamp ||  
        !nonce ||  
        !version  
    ) {  
        failure(req);  
        return blocked(res);  
    }  

    // Version  
    if (version !== VERSION) {  
        failure(req);  
        return blocked(res);  
    }  

    // Timestamp  
    if (!validTimestamp(timestamp)) {  
        failure(req);  
        return blocked(res);  
    }  

    // Nonce format  
    if (!validNonce(nonce)) {  
        failure(req);  
        return blocked(res);  
    }  

    // Replay protection  
    if (nonces.has(nonce)) {  
        failure(req);  
        return blocked(res);  
    }  

    nonces.set(  
        nonce,  
        now()  
    );  

    // Body must be {}  
    if (  
        !req.body ||  
        typeof req.body !== "object" ||  
        Array.isArray(req.body) ||  
        Object.keys(req.body).length !== 0  
    ) {  
        failure(req);  
        return blocked(res);  
    }  

    // Create session  
    const session =  
        createSession(  
            getIP(req)  
        );  

    // ====================================================  
    // RESPONSE  
    // ====================================================  

    return res.json({  

        ok: true,  

        version: VERSION,  

        session,  

        expiresIn:  
            SESSION_TTL,  

        config: {  

            soundId:  
                132545213997354,  

            volume: 4,  

            speed: 0.2  
        }  
    });  
}

);

// ============================================================
// CONFIG
// ============================================================

app.post(
"/api/config",
(req, res) => {

if (!checkRate(req)) {  
        return blocked(res);  
    }  

    const session =  
        req.header("X-Session");  

    if (  
        typeof session !== "string"  
    ) {  
        failure(req);  
        return blocked(res);  
    }  

    const record =  
        sessions.get(session);  

    if (!record) {  
        failure(req);  
        return blocked(res);  
    }  

    if (  
        record.expires <= now()  
    ) {  
        sessions.delete(session);  
        return blocked(res);  
    }  

    // Bind session to IP  
    if (  
        record.ip !== getIP(req)  
    ) {  
        failure(req);  
        return blocked(res);  
    }  

    if (  
        record.version !== VERSION  
    ) {  
        return blocked(res);  
    }  

    return res.json({  

        ok: true,  

        version: VERSION,  

        config: {  

            soundId:  
                132545213997354,  

            volume: 4,  

            speed: 0.2  
        }  
    });  
}

);

// ============================================================
// UNKNOWN ROUTES
// ============================================================

app.use(
(req, res) => {
return blocked(res);
}
);

// ============================================================
// ERROR HANDLER
// ============================================================

app.use(
(err, req, res, next) => {

console.error(  
        "[LEXINX ERROR]",  
        err.message  
    );  

    return blocked(res);  
}

);

// ============================================================
// CLEANUP
// ============================================================

setInterval(() => {

const t = now();  

for (  
    const [nonce, created]  
    of nonces  
) {  
    if (  
        t - created >  
        NONCE_TTL  
    ) {  
        nonces.delete(nonce);  
    }  
}  

for (  
    const [session, data]  
    of sessions  
) {  
    if (  
        data.expires <= t  
    ) {  
        sessions.delete(session);  
    }  
}  

for (  
    const [ip, state]  
    of clients  
) {  
    if (  
        state.lockedUntil < t &&  
        t - state.window >  
            RATE_WINDOW * 10  
    ) {  
        clients.delete(ip);  
    }  
}

}, 30_000);

// ============================================================
// START
// ============================================================

app.listen(
PORT,
() => {

console.log(  
        `[LEXINX ${VERSION}] ONLINE`  
    );  
}

);=================================================

app.get(
    "/",
    (req, res) => {

        res
            .status(200)
            .type("text/plain")
            .send("cc");
    }
);

// ============================================================
// PUBLIC LOADER
// ============================================================

app.get(
    "/api/66667777",
    (req, res) => {

        const loader = `
local HttpService =
    game:GetService("HttpService")

local API =
    "https://l3xinx-api.onrender.com/api/challenge"

local SESSION_API =
    "https://l3xinx-api.onrender.com/api/session"

local VERSION =
    "V60"

local function makeNonce()

    local chars =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    local result = {}

    for i = 1, 32 do

        local n =
            math.random(
                1,
                #chars
            )

        result[i] =
            chars:sub(
                n,
                n
            )
    end

    return table.concat(
        result
    )
end

local function requestAPI(
    url,
    nonce
)

    local response

    local ok =
        pcall(function()

            response =
                request({

                    Url = url,

                    Method = "POST",

                    Headers = {

                        ["Content-Type"] =
                            "application/json",

                        ["X-Time"] =
                            tostring(
                                os.time()
                            ),

                        ["X-Nonce"] =
                            nonce,

                        ["X-Version"] =
                            VERSION
                    },

                    Body = "{}"
                })

        end)

    if not ok then
        return nil
    end

    return response
end

-- ========================================================
-- CHALLENGE
-- ========================================================

local challengeResponse =
    requestAPI(
        API,
        makeNonce()
    )

if not challengeResponse or
   challengeResponse.StatusCode ~= 200 then

    warn(
        "[LEXINX] Challenge blocked"
    )

    return
end

local decoded,
      challengeData =
    pcall(function()

        return HttpService:JSONDecode(
            challengeResponse.Body
        )

    end)

if not decoded or
   type(challengeData) ~= "table" or
   challengeData.ok ~= true then

    warn(
        "[LEXINX] Invalid challenge"
    )

    return
end

local challenge =
    challengeData.challenge

if type(challenge) ~= "string" then
    return
end

-- ========================================================
-- SESSION
-- ========================================================

local sessionResponse

local sessionOK =
    pcall(function()

        sessionResponse =
            request({

                Url = SESSION_API,

                Method = "POST",

                Headers = {

                    ["Content-Type"] =
                        "application/json",

                    ["X-Time"] =
                        tostring(
                            os.time()
                        ),

                    ["X-Nonce"] =
                        makeNonce(),

                    ["X-Version"] =
                        VERSION,

                    ["X-Challenge"] =
                        challenge
                },

                Body = "{}"
            })

    end)

if not sessionOK or
   not sessionResponse or
   sessionResponse.StatusCode ~= 200 then

    warn(
        "[LEXINX] Session blocked"
    )

    return
end

local sessionDecoded,
      data =
    pcall(function()

        return HttpService:JSONDecode(
            sessionResponse.Body
        )

    end)

if not sessionDecoded or
   type(data) ~= "table" or
   data.ok ~= true then

    warn(
        "[LEXINX] Authorization failed"
    )

    return
end

if data.version ~= VERSION then

    warn(
        "[LEXINX] Version mismatch"
    )

    return
end

if type(data.session) ~= "string" then

    warn(
        "[LEXINX] Invalid session"
    )

    return
end

local config =
    data.config

if type(config) ~= "table" then
    return
end

print(
    "[LEXINX] Authorized"
)

-- ========================================================
-- EXAMPLE PAYLOAD
-- ========================================================

local Players =
    game:GetService("Players")

local player =
    Players.LocalPlayer

local character =
    player.Character or
    player.CharacterAdded:Wait()

local root =
    character:WaitForChild(
        "HumanoidRootPart"
    )

local sound =
    Instance.new("Sound")

sound.SoundId =
    "rbxassetid://" ..
    tostring(
        config.soundId
    )

sound.Volume =
    tonumber(
        config.volume
    ) or 4

sound.PlaybackSpeed =
    tonumber(
        config.speed
    ) or 0.2

sound.Parent =
    root

sound:Play()

sound.Ended:Once(
    function()

        sound:Destroy()

    end
)
`;

        res
            .status(200)
            .type("text/plain")
            .send(loader);
    }
);

// ============================================================
// CHALLENGE GET BLOCK
// ============================================================

app.get(
    "/api/challenge",
    (req, res) => {

        return blocked(res);
    }
);

// ============================================================
// CHALLENGE POST
// ============================================================

app.post(
    "/api/challenge",
    async (req, res) => {

        try {

            const ip =
                getIP(req);

            if (
                await isLocked(ip)
            ) {
                return blocked(res);
            }

            if (
                !await rateLimit(
                    ip,
                    "challenge",
                    LIMITS.challengePerMinute
                )
            ) {

                await registerFailure(
                    ip
                );

                return blocked(res);
            }

            const contentType =
                String(
                    req.headers[
                        "content-type"
                    ] || ""
                ).toLowerCase();

            if (
                !contentType.startsWith(
                    "application/json"
                )
            ) {

                await registerFailure(
                    ip
                );

                return blocked(res);
            }

            const timestamp =
                req.header(
                    "X-Time"
                );

            const nonce =
                req.header(
                    "X-Nonce"
                );

            const version =
                req.header(
                    "X-Version"
                );

            if (
                version !== VERSION ||
                !validTimestamp(timestamp) ||
                !validNonce(nonce)
            ) {

                await registerFailure(
                    ip
                );

                return blocked(res);
            }

            if (
                !await consumeNonce(
                    nonce
                )
            ) {

                await registerFailure(
                    ip
                );

                return blocked(res);
            }

            if (
                !emptyBody(req)
            ) {

                await registerFailure(
                    ip
                );

                return blocked(res);
            }

            // --------------------------------------------
            // Challenge
            // --------------------------------------------

            const challenge =
                randomHex(32);

            const fingerprint =
                getFingerprint(req);

            await redis.hSet(
                keyChallenge(
                    challenge
                ),
                {
                    ip,
                    fingerprint,
                    version: VERSION,
                    created:
                        String(now()),
                    expires:
                        String(
                            now() +
                            LIMITS.challengeTTL *
                            1000
                        )
                }
            );

            await redis.expire(
                keyChallenge(
                    challenge
                ),
                LIMITS.challengeTTL
            );

            return res.json({

                ok: true,

                version:
                    VERSION,

                challenge,

                expiresIn:
                    LIMITS.challengeTTL

            });

        } catch (err) {

            console.error(
                "[CHALLENGE]",
                err.message
            );

            return blocked(res);
        }
    }
);

// ============================================================
// SESSION GET BLOCK
// ============================================================

app.get(
    "/api/session",
    (req, res) => {

        return blocked(res);
    }
);

// ============================================================
// SESSION POST
// ============================================================

app.post(
    "/api/session",
    async (req, res) => {

        try {

            const ip =
                getIP(req);

            if (
                await isLocked(ip)
            ) {
                return blocked(res);
            }

            if (
                !await rateLimit(
                    ip,
                    "session",
                    LIMITS.sessionPerMinute
                )
            ) {

                await registerFailure(
                    ip
                );

                return blocked(res);
            }

            const timestamp =
                req.header(
                    "X-Time"
                );

            const nonce =
                req.header(
                    "X-Nonce"
                );

            const version =
                req.header(
                    "X-Version"
                );

            const challenge =
                req.header(
                    "X-Challenge"
                );

            if (
                version !== VERSION ||
                !validTimestamp(timestamp) ||
                !validNonce(nonce) ||
                typeof challenge !==
                    "string"
            ) {

                await registerFailure(
                    ip
                );

                return blocked(res);
            }

            if (
                !await consumeNonce(
                    nonce
                )
            ) {

                await registerFailure(
                    ip
                );

                return blocked(res);
            }

            // --------------------------------------------
            // Challenge lookup
            // --------------------------------------------

            const challengeKey =
                keyChallenge(
                    challenge
                );

            const record =
                await redis.hGetAll(
                    challengeKey
                );

            if (
                !record ||
                !record.ip
            ) {

                await registerFailure(
                    ip
                );

                return blocked(res);
            }

            if (
                record.ip !== ip ||
                record.version !== VERSION
            ) {

                await registerFailure(
                    ip
                );

                return blocked(res);
            }

            if (
                Number(record.expires) <=
                now()
            ) {

                await redis.del(
                    challengeKey
                );

                await registerFailure(
                    ip
                );

                return blocked(res);
            }

            // --------------------------------------------
            // Fingerprint
            // --------------------------------------------

            const fingerprint =
                getFingerprint(req);

            if (
                record.fingerprint !==
                fingerprint
            ) {

                await registerFailure(
                    ip
                );

                return blocked(res);
            }

            if (
                !emptyBody(req)
            ) {

                await registerFailure(
                    ip
                );

                return blocked(res);
            }

            // --------------------------------------------
            // Session limit
            // --------------------------------------------

            const active =
                await activeSessionsForIP(
                    ip
                );

            if (
                active >=
                LIMITS.maxSessionsPerIP
            ) {

                await registerFailure(
                    ip
                );

                return blocked(res);
            }

            // --------------------------------------------
            // One-time challenge
            // --------------------------------------------

            const deleted =
                await redis.del(
                    challengeKey
                );

            if (
                deleted !== 1
            ) {

                await registerFailure(
                    ip
                );

                return blocked(res);
            }

            // --------------------------------------------
            // Signed payload
            // --------------------------------------------

            const expires =
                now() +
                LIMITS.sessionTTL *
                1000;

            const session =
                randomHex(32);

            const payload = {

                version: VERSION,

                session,

                issuedAt: now(),

                expires,

                ip,

                fingerprint

            };

            const signature =
                signPayload(
                    payload
                );

            // --------------------------------------------
            // Store session
            // --------------------------------------------

            await redis.hSet(
                keySession(session),
                {
                    ip,
                    fingerprint,
                    version: VERSION,

                    created:
                        String(now()),

                    expires:
                        String(expires),

                    requests: "0",

                    signature
                }
            );

            await redis.expire(
                keySession(session),
                LIMITS.sessionTTL
            );

            // --------------------------------------------
            // Response
            // --------------------------------------------

            return res.json({

                ok: true,

                version:
                    VERSION,

                session,

                expiresIn:
                    LIMITS.sessionTTL *
                    1000,

                signed: {

                    payload,

                    signature

                },

                config: {

                    soundId:
                        132545213997354,

                    volume:
                        4,

                    speed:
                        0.2
                }

            });

        } catch (err) {

            console.error(
                "[SESSION]",
                err.message
            );

            return blocked(res);
        }
    }
);

// ============================================================
// CONFIG GET BLOCK
// ============================================================

app.get(
    "/api/config",
    (req, res) => {

        return blocked(res);
    }
);

// ============================================================
// CONFIG POST
// ============================================================

app.post(
    "/api/config",
    async (req, res) => {

        try {

            const ip =
                getIP(req);

            if (
                await isLocked(ip)
            ) {
                return blocked(res);
            }

            if (
                !await rateLimit(
                    ip,
                    "config",
                    LIMITS.configPerMinute
                )
            ) {

                await registerFailure(
                    ip
                );

                return blocked(res);
            }

            const session =
                req.header(
                    "X-Session"
                );

            if (
                !validSession(session)
            ) {

                await registerFailure(
                    ip
                );

                return blocked(res);
            }

            const key =
                keySession(
                    session
                );

            const record =
                await redis.hGetAll(
                    key
                );

            if (
                !record ||
                !record.ip
            ) {

                await registerFailure(
                    ip
                );

                return blocked(res);
            }

            if (
                record.ip !== ip
            ) {

                await registerFailure(
                    ip
                );

                return blocked(res);
            }

            if (
                record.version !== VERSION
            ) {

                return blocked(res);
            }

            if (
                Number(record.expires) <=
                now()
            ) {

                await redis.del(key);

                return blocked(res);
            }

            // --------------------------------------------
            // Fingerprint
            // --------------------------------------------

            const fingerprint =
                getFingerprint(req);

            if (
                record.fingerprint !==
                fingerprint
            ) {

                await registerFailure(
                    ip
                );

                return blocked(res);
            }

            // --------------------------------------------
            // Session request counter
            // --------------------------------------------

            const requests =
                await redis.hIncrBy(
                    key,
                    "requests",
                    1
                );

            if (
                requests >
                LIMITS.configPerMinute
            ) {

                await redis.del(key);

                return blocked(res);
            }

            // --------------------------------------------
            // Config
            // --------------------------------------------

            const payload = {

                version:
                    VERSION,

                session,

                issuedAt:
                    now(),

                expires:
                    Number(
                        record.expires
                    ),

                config: {

                    soundId:
                        132545213997354,

                    volume:
                        4,

                    speed:
                        0.2
                }

            };

            const signature =
                signPayload(
                    payload
                );

            return res.json({

                ok: true,

                version:
                    VERSION,

                signed: {

                    payload,

                    signature

                },

                config:
                    payload.config

            });

        } catch (err) {

            console.error(
                "[CONFIG]",
                err.message
            );

            return blocked(res);
        }
    }
);

// ============================================================
// UNKNOWN ROUTES
// ============================================================

app.use(
    (req, res) => {

        return blocked(res);
    }
);

// ============================================================
// ERROR HANDLER
// ============================================================

app.use(
    (err, req, res, next) => {

        console.error(
            "[LEXINX ERROR]",
            err.message
        );

        return blocked(res);
    }
);

// ============================================================
// START
// ============================================================

async function start() {

    try {

        await connectRedis();

        console.log(
            `[LEXINX ${VERSION}] REDIS CONNECTED`
        );

        app.listen(
            PORT,
            () => {

                console.log(
                    `[LEXINX ${VERSION}] ONLINE :${PORT}`
                );

            }
        );

    } catch (err) {

        console.error(
            "[LEXINX START FAILED]",
            err
        );

        process.exit(1);
    }
}

process.on(
    "SIGINT",
    async () => {

        if (redis.isOpen) {
            await redis.quit();
        }

        process.exit(0);
    }
);

process.on(
    "SIGTERM",
    async () => {

        if (redis.isOpen) {
            await redis.quit();
        }

        process.exit(0);
    }
);

start();