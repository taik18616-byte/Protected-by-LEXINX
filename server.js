"use strict";

const express = require("express");
const crypto = require("crypto");
const {
    createClient
} = require("redis");

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

const PORT =
    Number(process.env.PORT || 3000);

const VERSION = "V60";

const REDIS_URL =
    process.env.REDIS_URL;

const SERVER_SECRET =
    process.env.LEXINX_SECRET;

if (
    typeof REDIS_URL !== "string" ||
    !REDIS_URL.length
) {
    throw new Error(
        "REDIS_URL is required"
    );
}

if (
    typeof SERVER_SECRET !== "string" ||
    SERVER_SECRET.length < 32
) {
    throw new Error(
        "LEXINX_SECRET must contain at least 32 characters"
    );
}

// ============================================================
// LIMITS
// ============================================================

const LIMITS = {

    challengeTTL: 15,
    sessionTTL: 30,
    nonceTTL: 60,

    timestampSkew: 30,

    challengePerMinute: 5,
    sessionPerMinute: 5,
    configPerMinute: 20,

    maxSessionsPerIP: 3,

    maxFailures: 5,

    bodySize: 1024,

    fingerprintTTL: 120,

    replayTTL: 60
};

// ============================================================
// REDIS
// ============================================================

const redis =
    createClient({
        url: REDIS_URL
    });

redis.on(
    "error",
    err => {
        console.error(
            "[REDIS]",
            err.message
        );
    }
);

async function connectRedis() {

    if (!redis.isOpen) {
        await redis.connect();
    }
}

// ============================================================
// TIME
// ============================================================

function now() {
    return Date.now();
}

function unix() {
    return Math.floor(
        now() / 1000
    );
}

// ============================================================
// RANDOM
// ============================================================

function randomHex(
    bytes = 32
) {
    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

// ============================================================
// IP
// ============================================================

function getIP(req) {

    return (
        req.ip ||
        req.socket?.remoteAddress ||
        "unknown"
    );
}

// ============================================================
// FINGERPRINT
// ============================================================

function getFingerprint(req) {

    const userAgent =
        String(
            req.headers["user-agent"] ||
            ""
        );

    const accept =
        String(
            req.headers["accept"] ||
            ""
        );

    const language =
        String(
            req.headers["accept-language"] ||
            ""
        );

    return crypto
        .createHash("sha256")
        .update(
            [
                getIP(req),
                userAgent,
                accept,
                language,
                VERSION
            ].join("|")
        )
        .digest("hex");
}

// ============================================================
// BLOCK
// ============================================================

function blocked(res) {

    return res
        .status(403)
        .type("text/plain")
        .send(
            "Blocked by LEXINX v60 protection"
        );
}

// ============================================================
// SECURITY HEADERS
// ============================================================

app.use(
    (req, res, next) => {

        res.setHeader(
            "Cache-Control",
            "no-store, no-cache, must-revalidate"
        );

        res.setHeader(
            "Pragma",
            "no-cache"
        );

        res.setHeader(
            "Expires",
            "0"
        );

        res.setHeader(
            "X-Content-Type-Options",
            "nosniff"
        );

        res.setHeader(
            "Referrer-Policy",
            "no-referrer"
        );

        res.setHeader(
            "X-Frame-Options",
            "DENY"
        );

        next();
    }
);

// ============================================================
// BODY LIMIT
// ============================================================

app.use(
    (req, res, next) => {

        const length =
            Number(
                req.headers[
                    "content-length"
                ] || 0
            );

        if (
            Number.isFinite(length) &&
            length > LIMITS.bodySize
        ) {
            return blocked(res);
        }

        next();
    }
);

// ============================================================
// REDIS KEYS
// ============================================================

function keyNonce(nonce) {
    return `lexinx:${VERSION}:nonce:${nonce}`;
}

function keyChallenge(challenge) {
    return `lexinx:${VERSION}:challenge:${challenge}`;
}

function keySession(session) {
    return `lexinx:${VERSION}:session:${session}`;
}

function keyClient(ip) {
    return `lexinx:${VERSION}:client:${ip}`;
}

function keyRate(ip, type) {
    return `lexinx:${VERSION}:rate:${type}:${ip}`;
}

function keyReplay(value) {
    return `lexinx:${VERSION}:replay:${value}`;
}

// ============================================================
// REDIS RATE LIMIT
// ============================================================

async function rateLimit(
    ip,
    type,
    maximum
) {

    const key =
        keyRate(ip, type);

    const count =
        await redis.incr(key);

    if (count === 1) {

        await redis.expire(
            key,
            60
        );
    }

    return count <= maximum;
}

// ============================================================
// FAILURE / PROGRESSIVE LOCK
// ============================================================

async function registerFailure(
    ip
) {

    const key =
        keyClient(ip);

    const failures =
        await redis.hIncrBy(
            key,
            "failures",
            1
        );

    const lockLevels = [
        10,
        30,
        60,
        180,
        600,
        1800
    ];

    const index =
        Math.min(
            failures - 1,
            lockLevels.length - 1
        );

    const seconds =
        lockLevels[index];

    await redis.hSet(
        key,
        "lockedUntil",
        String(
            now() +
            seconds * 1000
        )
    );

    await redis.expire(
        key,
        3600
    );

    return seconds;
}

// ============================================================
// LOCK CHECK
// ============================================================

async function isLocked(
    ip
) {

    const key =
        keyClient(ip);

    const lockedUntil =
        Number(
            await redis.hGet(
                key,
                "lockedUntil"
            ) || 0
        );

    return lockedUntil > now();
}

// ============================================================
// NONCE
// ============================================================

function validNonce(value) {

    return (
        typeof value === "string" &&
        /^[A-Za-z0-9]{32}$/
            .test(value)
    );
}

async function consumeNonce(
    nonce
) {

    const result =
        await redis.set(
            keyNonce(nonce),
            "1",
            {
                NX: true,
                EX:
                    LIMITS.nonceTTL
            }
        );

    return result === "OK";
}

// ============================================================
// TIMESTAMP
// ============================================================

function validTimestamp(
    value
) {

    if (
        typeof value !== "string" ||
        !/^\d{10}$/.test(value)
    ) {
        return false;
    }

    const timestamp =
        Number(value);

    if (
        !Number.isSafeInteger(
            timestamp
        )
    ) {
        return false;
    }

    return (
        Math.abs(
            unix() - timestamp
        ) <=
        LIMITS.timestampSkew
    );
}

// ============================================================
// EMPTY BODY
// ============================================================

function emptyBody(req) {

    if (
        !req.body ||
        typeof req.body !== "object" ||
        Array.isArray(req.body)
    ) {
        return false;
    }

    return (
        Object.keys(req.body)
            .length === 0
    );
}

// ============================================================
// SIGNED PAYLOAD
// ============================================================

function signPayload(
    payload
) {

    const body =
        JSON.stringify(
            payload
        );

    return crypto
        .createHmac(
            "sha256",
            SERVER_SECRET
        )
        .update(body)
        .digest("hex");
}

// ============================================================
// SAFE SESSION TOKEN
// ============================================================

function validSession(
    value
) {

    return (
        typeof value === "string" &&
        /^[a-f0-9]{64}$/
            .test(value)
    );
}

// ============================================================
// ACTIVE SESSIONS
// ============================================================

async function activeSessionsForIP(
    ip
) {

    /*
     * Redis SCAN được dùng thay vì KEYS.
     * Với hệ thống rất lớn nên chuyển
     * phần này sang Redis Set để tối ưu hơn.
     */

    let cursor = "0";
    let count = 0;

    do {

        const result =
            await redis.scan(
                cursor,
                {
                    MATCH:
                        `lexinx:${VERSION}:session:*`,
                    COUNT: 100
                }
            );

        cursor =
            result.cursor;

        for (
            const key of result.keys
        ) {

            const data =
                await redis.hGetAll(
                    key
                );

            if (
                data.ip === ip &&
                Number(data.expires) >
                    now()
            ) {
                count++;
            }

            if (
                count >=
                LIMITS.maxSessionsPerIP
            ) {
                return count;
            }
        }

    } while (
        cursor !== "0"
    );

    return count;
}

// ============================================================
// HOME
// ============================================================

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