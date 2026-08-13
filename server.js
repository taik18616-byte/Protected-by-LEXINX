"use strict";

const express = require("express");
const crypto = require("crypto");

const app = express();

app.disable("x-powered-by");

/*
 * Chỉ bật trust proxy nếu server thực sự nằm sau
 * proxy mà bạn kiểm soát.
 *
 * Nếu dùng Cloudflare/Nginx:
 * có thể đặt:
 *
 * app.set("trust proxy", 1);
 *
 * Nếu expose Node trực tiếp:
 * KHÔNG bật trust proxy.
 */
app.set("trust proxy", 1);

// ============================================================
// BODY PARSER
// ============================================================

app.use(express.json({
    limit: "1kb",
    strict: true,
    type: "application/json"
}));

// ============================================================
// CONFIG
// ============================================================

const PORT =
    process.env.PORT || 3000;

const SERVER_SECRET =
    process.env.LEXINX_SECRET;

if (
    typeof SERVER_SECRET !== "string" ||
    SERVER_SECRET.length < 32
) {
    throw new Error(
        "LEXINX_SECRET must contain at least 32 characters"
    );
}

const VERSION = "V60";

const CONFIG = {

    // --------------------------------------------------------
    // TIME
    // --------------------------------------------------------

    challengeTTL:
        15_000,

    sessionTTL:
        30_000,

    nonceTTL:
        60_000,

    timestampSkew:
        30,

    // --------------------------------------------------------
    // RATE LIMIT
    // --------------------------------------------------------

    challengePerMinute:
        5,

    sessionPerMinute:
        5,

    configPerMinute:
        20,

    // --------------------------------------------------------
    // SESSION
    // --------------------------------------------------------

    maxSessionsPerIP:
        3,

    maxConfigRequests:
        20,

    // --------------------------------------------------------
    // FAILURE
    // --------------------------------------------------------

    maxFailures:
        5,

    // --------------------------------------------------------
    // REQUEST
    // --------------------------------------------------------

    maxBodySize:
        1024,

    // --------------------------------------------------------
    // CLEANUP
    // --------------------------------------------------------

    cleanupInterval:
        15_000
};

// ============================================================
// MEMORY
// ============================================================

const challenges =
    new Map();

const nonces =
    new Map();

const sessions =
    new Map();

const clients =
    new Map();

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

function randomHex(bytes = 32) {

    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

// ============================================================
// IP
// ============================================================

function getIP(req) {

    /*
     * req.ip được Express xử lý dựa trên
     * trust proxy configuration.
     *
     * Không tự lấy X-Forwarded-For.
     */

    return (
        req.ip ||
        req.socket?.remoteAddress ||
        "unknown"
    );
}

// ============================================================
// BLOCK
// ============================================================

function blocked(res) {

    return res
        .status(403)
        .type("text/plain")
        .send(
            "Blocked by LEXINX V60 protection"
        );
}

// ============================================================
// SECURITY HEADERS
// ============================================================

app.use((req, res, next) => {

    res.setHeader(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, private"
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

    res.setHeader(
        "Content-Security-Policy",
        "default-src 'none'"
    );

    res.setHeader(
        "Cross-Origin-Resource-Policy",
        "same-origin"
    );

    next();
});

// ============================================================
// REQUEST SIZE
// ============================================================

app.use((req, res, next) => {

    const length =
        Number(
            req.headers[
                "content-length"
            ] || 0
        );

    if (
        Number.isFinite(length) &&
        length > CONFIG.maxBodySize
    ) {
        return blocked(res);
    }

    next();
});

// ============================================================
// CLIENT STATE
// ============================================================

function getClient(ip) {

    let state =
        clients.get(ip);

    if (!state) {

        state = {

            challengeWindow:
                now(),

            challengeCount:
                0,

            sessionWindow:
                now(),

            sessionCount:
                0,

            configWindow:
                now(),

            configCount:
                0,

            failures:
                0,

            lockLevel:
                0,

            lockedUntil:
                0,

            lastSeen:
                now()
        };

        clients.set(
            ip,
            state
        );
    }

    state.lastSeen =
        now();

    return state;
}

// ============================================================
// LOCK
// ============================================================

const LOCK_LEVELS = [

    10_000,
    30_000,
    60_000,
    180_000,
    600_000,
    1_800_000
];

function registerFailure(ip) {

    const state =
        getClient(ip);

    state.failures++;

    const index =
        Math.min(
            state.lockLevel,
            LOCK_LEVELS.length - 1
        );

    state.lockedUntil =
        now() +
        LOCK_LEVELS[index];

    state.lockLevel++;

    if (
        state.failures >=
        CONFIG.maxFailures
    ) {

        state.lockedUntil =
            now() +
            LOCK_LEVELS[
                LOCK_LEVELS.length - 1
            ];
    }
}

function isLocked(ip) {

    const state =
        getClient(ip);

    return (
        state.lockedUntil >
        now()
    );
}

// ============================================================
// RATE LIMIT
// ============================================================

function rateLimit(
    req,
    type
) {

    const ip =
        getIP(req);

    const state =
        getClient(ip);

    if (
        state.lockedUntil >
        now()
    ) {
        return false;
    }

    let windowKey;
    let countKey;
    let maximum;

    switch (type) {

        case "challenge":

            windowKey =
                "challengeWindow";

            countKey =
                "challengeCount";

            maximum =
                CONFIG.challengePerMinute;

            break;

        case "session":

            windowKey =
                "sessionWindow";

            countKey =
                "sessionCount";

            maximum =
                CONFIG.sessionPerMinute;

            break;

        case "config":

            windowKey =
                "configWindow";

            countKey =
                "configCount";

            maximum =
                CONFIG.configPerMinute;

            break;

        default:

            return false;
    }

    if (
        now() -
        state[windowKey] >=
        60_000
    ) {

        state[windowKey] =
            now();

        state[countKey] =
            0;
    }

    state[countKey]++;

    if (
        state[countKey] >
        maximum
    ) {

        state.lockedUntil =
            now() + 60_000;

        return false;
    }

    return true;
}

// ============================================================
// HEADER VALIDATION
// ============================================================

function validNonce(value) {

    return (
        typeof value === "string" &&
        /^[A-Za-z0-9]{32}$/.test(
            value
        )
    );
}

function validTimestamp(value) {

    if (
        typeof value !== "string"
    ) {
        return false;
    }

    if (
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
            unix() -
            timestamp
        ) <=
        CONFIG.timestampSkew
    );
}

function validVersion(value) {

    return (
        typeof value === "string" &&
        value === VERSION
    );
}

// ============================================================
// NONCE
// ============================================================

function consumeNonce(nonce) {

    if (
        nonces.has(nonce)
    ) {
        return false;
    }

    nonces.set(
        nonce,
        now()
    );

    return true;
}

// ============================================================
// EMPTY JSON BODY
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
// SESSION TOKEN
// ============================================================

function createSessionToken() {

    return randomHex(32);
}

// ============================================================
// HMAC
// ============================================================

function createServerSignature(
    challenge,
    nonce,
    version,
    ip
) {

    return crypto
        .createHmac(
            "sha256",
            SERVER_SECRET
        )
        .update(
            [
                challenge,
                nonce,
                version,
                ip
            ].join(".")
        )
        .digest("hex");
}

// ============================================================
// CONSTANT TIME
// ============================================================

function safeEqual(
    a,
    b
) {

    if (
        typeof a !== "string" ||
        typeof b !== "string"
    ) {
        return false;
    }

    const A =
        Buffer.from(a);

    const B =
        Buffer.from(b);

    if (
        A.length !==
        B.length
    ) {
        return false;
    }

    return crypto.timingSafeEqual(
        A,
        B
    );
}

// ============================================================
// ACTIVE SESSIONS
// ============================================================

function activeSessionsForIP(ip) {

    const t =
        now();

    let count =
        0;

    for (
        const session
        of sessions.values()
    ) {

        if (
            session.ip === ip &&
            session.expires > t
        ) {

            count++;
        }
    }

    return count;
}

// ============================================================
// SESSION LOOKUP
// ============================================================

function getValidSession(
    session,
    ip
) {

    if (
        typeof session !== "string"
    ) {
        return null;
    }

    if (
        !/^[a-f0-9]{64}$/.test(
            session
        )
    ) {
        return null;
    }

    const record =
        sessions.get(session);

    if (!record) {
        return null;
    }

    if (
        record.expires <=
        now()
    ) {

        sessions.delete(
            session
        );

        return null;
    }

    if (
        record.version !==
        VERSION
    ) {
        return null;
    }

    if (
        record.ip !== ip
    ) {
        return null;
    }

    return record;
}

// ============================================================
// HOME
// ============================================================

app.get(
    "/",
    (req, res) => {

        return res
            .status(200)
            .type("text/plain")
            .send("cc");
    }
);

// ============================================================
// PUBLIC BOOTSTRAP
// ============================================================

app.get(
    "/api/66667777",
    (req, res) => {

        /*
         * PUBLIC ENDPOINT.
         *
         * Không chứa:
         *
         * - SERVER_SECRET
         * - API key
         * - session token
         * - payload bí mật
         *
         * Đây chỉ là bootstrap.
         */

        const bootstrap = `

local HttpService =
    game:GetService("HttpService")

local Players =
    game:GetService("Players")

local API =
    "https://YOUR-DOMAIN/api/challenge"

local SESSION_API =
    "https://YOUR-DOMAIN/api/session"

local VERSION =
    "V60"

-- =========================================================
-- NONCE
-- =========================================================

local function makeNonce()

    local chars =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    local result = {}

    for i = 1, 32 do

        local index =
            math.random(
                1,
                #chars
            )

        result[i] =
            chars:sub(
                index,
                index
            )
    end

    return table.concat(
        result
    )
end

-- =========================================================
-- REQUEST
-- =========================================================

local function sendRequest(
    url,
    headers
)

    local response

    local ok =
        pcall(function()

            response =
                request({

                    Url =
                        url,

                    Method =
                        "POST",

                    Headers =
                        headers,

                    Body =
                        "{}"
                })

        end)

    if not ok then
        return nil
    end

    if not response then
        return nil
    end

    if response.StatusCode ~= 200 then
        return nil
    end

    return response
end

-- =========================================================
-- CHALLENGE
-- =========================================================

local challengeNonce =
    makeNonce()

local challengeTime =
    tostring(os.time())

local challengeResponse =
    sendRequest(

        API,

        {

            ["Content-Type"] =
                "application/json",

            ["X-Time"] =
                challengeTime,

            ["X-Nonce"] =
                challengeNonce,

            ["X-Version"] =
                VERSION
        }
    )

if not challengeResponse then

    warn(
        "[LEXINX V60] Challenge blocked"
    )

    return
end

local challengeOK,
      challengeData =
    pcall(function()

        return HttpService:JSONDecode(
            challengeResponse.Body
        )

    end)

if not challengeOK or
   type(challengeData) ~= "table" or
   challengeData.ok ~= true then

    warn(
        "[LEXINX V60] Invalid challenge"
    )

    return
end

if challengeData.version ~= VERSION then

    warn(
        "[LEXINX V60] Version mismatch"
    )

    return
end

local challenge =
    challengeData.challenge

if type(challenge) ~= "string" then

    warn(
        "[LEXINX V60] Invalid challenge"
    )

    return
end

-- =========================================================
-- SESSION
-- =========================================================

local sessionNonce =
    makeNonce()

local sessionTime =
    tostring(os.time())

local sessionResponse =
    sendRequest(

        SESSION_API,

        {

            ["Content-Type"] =
                "application/json",

            ["X-Time"] =
                sessionTime,

            ["X-Nonce"] =
                sessionNonce,

            ["X-Version"] =
                VERSION,

            ["X-Challenge"] =
                challenge
        }
    )

if not sessionResponse then

    warn(
        "[LEXINX V60] Session blocked"
    )

    return
end

local sessionOK,
      data =
    pcall(function()

        return HttpService:JSONDecode(
            sessionResponse.Body
        )

    end)

if not sessionOK or
   type(data) ~= "table" or
   data.ok ~= true then

    warn(
        "[LEXINX V60] Authorization failed"
    )

    return
end

if data.version ~= VERSION then

    warn(
        "[LEXINX V60] Version mismatch"
    )

    return
end

if type(data.session) ~= "string" then

    warn(
        "[LEXINX V60] Invalid session"
    )

    return
end

print(
    "[LEXINX V60] Authorized"
)

-- =========================================================
-- CONFIG
-- =========================================================

local config =
    data.config

if type(config) ~= "table" then
    return
end

local soundId =
    tonumber(config.soundId)

local volume =
    tonumber(config.volume)

local speed =
    tonumber(config.speed)

if not soundId then
    return
end

volume =
    volume or 4

speed =
    speed or 0.2

-- =========================================================
-- SOUND
-- =========================================================

local player =
    Players.LocalPlayer

if not player then
    return
end

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
    tostring(soundId)

sound.Volume =
    volume

sound.PlaybackSpeed =
    speed

sound.Parent =
    root

sound:Play()

sound.Ended:Once(
    function()

        if sound then
            sound:Destroy()
        end

    end
)

`;

        return res
            .status(200)
            .type("text/plain")
            .send(bootstrap);
    }
);

// ============================================================
// CHALLENGE GET = BLOCK
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
    (req, res) => {

        const ip =
            getIP(req);

        // ----------------------------------------------------
        // LOCK
        // ----------------------------------------------------

        if (
            isLocked(ip)
        ) {
            return blocked(res);
        }

        // ----------------------------------------------------
        // RATE
        // ----------------------------------------------------

        if (
            !rateLimit(
                req,
                "challenge"
            )
        ) {
            return blocked(res);
        }

        // ----------------------------------------------------
        // CONTENT TYPE
        // ----------------------------------------------------

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

            registerFailure(ip);

            return blocked(res);
        }

        // ----------------------------------------------------
        // HEADERS
        // ----------------------------------------------------

        const timestamp =
            req.header("X-Time");

        const nonce =
            req.header("X-Nonce");

        const version =
            req.header("X-Version");

        if (
            !validTimestamp(timestamp) ||
            !validNonce(nonce) ||
            !validVersion(version)
        ) {

            registerFailure(ip);

            return blocked(res);
        }

        // ----------------------------------------------------
        // NONCE
        // ----------------------------------------------------

        if (
            !consumeNonce(nonce)
        ) {

            registerFailure(ip);

            return blocked(res);
        }

        // ----------------------------------------------------
        // BODY
        // ----------------------------------------------------

        if (
            !emptyBody(req)
        ) {

            registerFailure(ip);

            return blocked(res);
        }

        // ----------------------------------------------------
        // CREATE CHALLENGE
        // ----------------------------------------------------

        const challenge =
            randomHex(32);

        challenges.set(
            challenge,
            {

                ip,

                version:
                    VERSION,

                created:
                    now(),

                expires:
                    now() +
                    CONFIG.challengeTTL,

                used:
                    false
            }
        );

        return res
            .status(200)
            .json({

                ok:
                    true,

                version:
                    VERSION,

                challenge,

                expiresIn:
                    CONFIG.challengeTTL
            });
    }
);

// ============================================================
// SESSION GET = BLOCK
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
    (req, res) => {

        const ip =
            getIP(req);

        // ----------------------------------------------------
        // LOCK
        // ----------------------------------------------------

        if (
            isLocked(ip)
        ) {
            return blocked(res);
        }

        // ----------------------------------------------------
        // RATE
        // ----------------------------------------------------

        if (
            !rateLimit(
                req,
                "session"
            )
        ) {
            return blocked(res);
        }

        // ----------------------------------------------------
        // SESSION/IP LIMIT
        // ----------------------------------------------------

        if (
            activeSessionsForIP(ip) >=
            CONFIG.maxSessionsPerIP
        ) {

            return blocked(res);
        }

        // ----------------------------------------------------
        // CONTENT TYPE
        // ----------------------------------------------------

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

            registerFailure(ip);

            return blocked(res);
        }

        // ----------------------------------------------------
        // HEADERS
        // ----------------------------------------------------

        const timestamp =
            req.header("X-Time");

        const nonce =
            req.header("X-Nonce");

        const version =
            req.header("X-Version");

        const challenge =
            req.header("X-Challenge");

        if (
            !validTimestamp(timestamp) ||
            !validNonce(nonce) ||
            !validVersion(version) ||
            typeof challenge !==
                "string" ||
            !/^[a-f0-9]{64}$/
                .test(challenge)
        ) {

            registerFailure(ip);

            return blocked(res);
        }

        // ----------------------------------------------------
        // NONCE
        // ----------------------------------------------------

        if (
            !consumeNonce(nonce)
        ) {

            registerFailure(ip);

            return blocked(res);
        }

        // ----------------------------------------------------
        // CHALLENGE
        // ----------------------------------------------------

        const record =
            challenges.get(
                challenge
            );

        if (!record) {

            registerFailure(ip);

            return blocked(res);
        }

        // ----------------------------------------------------
        // ONE-TIME
        // ----------------------------------------------------

        if (
            record.used
        ) {

            challenges.delete(
                challenge
            );

            registerFailure(ip);

            return blocked(res);
        }

        // ----------------------------------------------------
        // EXPIRATION
        // ----------------------------------------------------

        if (
            record.expires <=
            now()
        ) {

            challenges.delete(
                challenge
            );

            registerFailure(ip);

            return blocked(res);
        }

        // ----------------------------------------------------
        // VERSION
        // ----------------------------------------------------

        if (
            record.version !==
            VERSION
        ) {

            registerFailure(ip);

            return blocked(res);
        }

        // ----------------------------------------------------
        // IP BINDING
        // ----------------------------------------------------

        if (
            record.ip !==
            ip
        ) {

            registerFailure(ip);

            return blocked(res);
        }

        // ----------------------------------------------------
        // BODY
        // ----------------------------------------------------

        if (
            !emptyBody(req)
        ) {

            registerFailure(ip);

            return blocked(res);
        }

        // ----------------------------------------------------
        // CONSUME CHALLENGE
        // ----------------------------------------------------

        record.used =
            true;

        challenges.delete(
            challenge
        );

        // ----------------------------------------------------
        // SERVER SIGNATURE
        // ----------------------------------------------------

        const signature =
            createServerSignature(
                challenge,
                nonce,
                VERSION,
                ip
            );

        // ----------------------------------------------------
        // SESSION
        // ----------------------------------------------------

        const session =
            createSessionToken();

        sessions.set(
            session,
            {

                ip,

                version:
                    VERSION,

                created:
                    now(),

                expires:
                    now() +
                    CONFIG.sessionTTL,

                requests:
                    0,

                signature
            }
        );

        // ----------------------------------------------------
        // RESPONSE
        // ----------------------------------------------------

        return res
            .status(200)
            .json({

                ok:
                    true,

                version:
                    VERSION,

                session,

                expiresIn:
                    CONFIG.sessionTTL,

                config: {

                    soundId:
                        132545213997354,

                    volume:
                        4,

                    speed:
                        0.2
                }
            });
    }
);

// ============================================================
// CONFIG GET = BLOCK
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
    (req, res) => {

        const ip =
            getIP(req);

        // ----------------------------------------------------
        // LOCK
        // ----------------------------------------------------

        if (
            isLocked(ip)
        ) {
            return blocked(res);
        }

        // ----------------------------------------------------
        // RATE
        // ----------------------------------------------------

        if (
            !rateLimit(
                req,
                "config"
            )
        ) {
            return blocked(res);
        }

        // ----------------------------------------------------
        // CONTENT TYPE
        // ----------------------------------------------------

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

            registerFailure(ip);

            return blocked(res);
        }

        // ----------------------------------------------------
        // SESSION
        // ----------------------------------------------------

        const session =
            req.header(
                "X-Session"
            );

        if (
            typeof session !==
                "string" ||
            session.length !== 64
        ) {

            registerFailure(ip);

            return blocked(res);
        }

        // ----------------------------------------------------
        // SESSION LOOKUP
        // ----------------------------------------------------

        const record =
            getValidSession(
                session,
                ip
            );

        if (!record) {

            registerFailure(ip);

            return blocked(res);
        }

        // ----------------------------------------------------
        // BODY
        // ----------------------------------------------------

        if (
            !emptyBody(req)
        ) {

            registerFailure(ip);

            return blocked(res);
        }

        // ----------------------------------------------------
        // REQUEST COUNT
        // ----------------------------------------------------

        record.requests++;

        if (
            record.requests >
            CONFIG.maxConfigRequests
        ) {

            sessions.delete(
                session
            );

            return blocked(res);
        }

        // ----------------------------------------------------
        // RESPONSE
        // ----------------------------------------------------

        return res
            .status(200)
            .json({

                ok:
                    true,

                version:
                    VERSION,

                config: {

                    soundId:
                        132545213997354,

                    volume:
                        4,

                    speed:
                        0.2
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
            "[LEXINX V60]",
            err?.message ||
            "Unknown error"
        );

        return blocked(res);
    }
);

// ============================================================
// CLEANUP
// ============================================================

setInterval(
    () => {

        const t =
            now();

        // ----------------------------------------------------
        // NONCES
        // ----------------------------------------------------

        for (
            const [
                nonce,
                created
            ] of nonces
        ) {

            if (
                t - created >
                CONFIG.nonceTTL
            ) {

                nonces.delete(
                    nonce
                );
            }
        }

        // ----------------------------------------------------
        // CHALLENGES
        // ----------------------------------------------------

        for (
            const [
                challenge,
                data
            ] of challenges
        ) {

            if (
                data.expires <=
                t
            ) {

                challenges.delete(
                    challenge
                );
            }
        }

        // ----------------------------------------------------
        // SESSIONS
        // ----------------------------------------------------

        for (
            const [
                session,
                data
            ] of sessions
        ) {

            if (
                data.expires <=
                t
            ) {

                sessions.delete(
                    session
                );
            }
        }

        // ----------------------------------------------------
        // CLIENT STATE
        // ----------------------------------------------------

        for (
            const [
                ip,
                state
            ] of clients
        ) {

            const inactive =
                t -
                state.lastSeen;

            if (
                state.lockedUntil <= t &&
                inactive >
                    600_000
            ) {

                clients.delete(
                    ip
                );
            }
        }

    },
    CONFIG.cleanupInterval
);

// ============================================================
// START
// ============================================================

const server =
    app.listen(
        PORT,
        () => {

            console.log(
                `[LEXINX ${VERSION}] ONLINE`
            );

            console.log(
                `[LEXINX ${VERSION}] Port: ${PORT}`
            );
        }
    );

// ============================================================
// SERVER ERROR
// ============================================================

server.on(
    "error",
    (err) => {

        console.error(
            "[LEXINX SERVER ERROR]",
            err.message
        );

        process.exit(1);
    }
);

// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================

function shutdown(signal) {

    console.log(
        `[LEXINX ${VERSION}] ${signal}`
    );

    server.close(
        () => {

            console.log(
                `[LEXINX ${VERSION}] CLOSED`
            );

            process.exit(0);
        }
    );
}

process.on(
    "SIGTERM",
    () => shutdown("SIGTERM")
);

process.on(
    "SIGINT",
    () => shutdown("SIGINT")
);