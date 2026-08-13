const express = require("express");
const crypto = require("crypto");

const app = express();

app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use(express.json({
    limit: "2kb",
    strict: true
}));

const PORT = process.env.PORT || 3000;

const TOKEN =
    process.env.LEXINX_TOKEN || "CHANGE_ME";

const VERSION = "V50";

const NONCE_TTL = 60_000;
const SESSION_TTL = 30_000;

const RATE_WINDOW = 60_000;
const MAX_REQUESTS = 20;
const MAX_FAILURES = 5;
const LOCK_TIME = 300_000;

const nonces = new Map();
const sessions = new Map();
const clients = new Map();


// ============================================================
// FAKE / DECOY PAYLOADS
// ============================================================

const DECOYS = [
    {
        id: "payload_001",
        version: "V49",
        ok: false,
        payload: "INVALID",
        checksum: "00000000"
    },

    {
        id: "payload_002",
        version: "V48",
        ok: false,
        payload: null,
        checksum: "FFFFFFFF"
    },

    {
        id: "payload_003",
        version: "TEST",
        ok: false,
        payload: "DECOY_PAYLOAD",
        checksum: "12345678"
    },

    {
        id: "payload_004",
        version: "DEBUG",
        ok: false,
        payload: "DISABLED",
        checksum: "AAAAAAAA"
    },

    {
        id: "payload_005",
        version: "V00",
        ok: false,
        payload: "BLOCKED",
        checksum: "BBBBBBBB"
    },

    {
        id: "payload_006",
        version: "FAKE",
        ok: false,
        payload: "NOT_AUTHORIZED",
        checksum: "CCCCCCCC"
    }
];


// ============================================================
// UTILS
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

function getClient(ip) {

    let client = clients.get(ip);

    if (!client) {

        client = {
            windowStart: now(),
            requests: 0,
            failures: 0,
            lockedUntil: 0
        };

        clients.set(ip, client);
    }

    return client;
}


// ============================================================
// RATE LIMIT
// ============================================================

function checkRate(req) {

    const client =
        getClient(getIP(req));

    if (
        client.lockedUntil >
        now()
    ) {
        return false;
    }

    if (
        now() -
        client.windowStart >
        RATE_WINDOW
    ) {

        client.windowStart = now();
        client.requests = 0;
    }

    client.requests++;

    if (
        client.requests >
        MAX_REQUESTS
    ) {

        client.lockedUntil =
            now() + LOCK_TIME;

        return false;
    }

    return true;
}


// ============================================================
// FAILURE
// ============================================================

function registerFailure(req) {

    const client =
        getClient(getIP(req));

    client.failures++;

    if (
        client.failures >=
        MAX_FAILURES
    ) {

        client.lockedUntil =
            now() + LOCK_TIME;
    }
}


// ============================================================
// TOKEN
// ============================================================

function validToken(token) {

    if (
        typeof token !==
        "string"
    ) {
        return false;
    }

    const expected =
        Buffer.from(TOKEN);

    const supplied =
        Buffer.from(token);

    if (
        expected.length !==
        supplied.length
    ) {
        return false;
    }

    return crypto.timingSafeEqual(
        expected,
        supplied
    );
}


// ============================================================
// NONCE
// ============================================================

function validNonce(nonce) {

    return (
        typeof nonce ===
            "string" &&
        /^[A-Za-z0-9]{32}$/
            .test(nonce)
    );
}


// ============================================================
// SECURITY HEADERS
// ============================================================

app.use((req, res, next) => {

    res.setHeader(
        "Cache-Control",
        "no-store, no-cache, must-revalidate"
    );

    res.setHeader(
        "Pragma",
        "no-cache"
    );

    res.setHeader(
        "X-Content-Type-Options",
        "nosniff"
    );

    next();
});


// ============================================================
// HOME
// ============================================================

app.get("/", (req, res) => {

    res
        .type("text/plain")
        .send("cc");
});


// ============================================================
// FAKE ENDPOINTS
// ============================================================

app.get(
    "/api/test",
    (req, res) => {

        return res.json(
            DECOYS[0]
        );
    }
);

app.get(
    "/api/debug",
    (req, res) => {

        return res.json(
            DECOYS[1]
        );
    }
);

app.get(
    "/api/version",
    (req, res) => {

        return res.json(
            DECOYS[2]
        );
    }
);

app.get(
    "/api/payload",
    (req, res) => {

        return res.json(
            DECOYS[3]
        );
    }
);

app.get(
    "/api/legacy",
    (req, res) => {

        return res.json(
            DECOYS[4]
        );
    }
);


// ============================================================
// REAL LOADER
// ============================================================

app.get(
    "/api/66667777",
    (req, res) => {

        const bootstrap = `
local HttpService = game:GetService("HttpService")

local API =
    "https://YOUR-DOMAIN/api/session"

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

local response =
    request({

        Url = API,

        Method = "POST",

        Headers = {

            ["Content-Type"] =
                "application/json",

            ["X-Time"] =
                tostring(
                    os.time()
                ),

            ["X-Nonce"] =
                nonce(),

            ["X-Version"] =
                VERSION
        },

        Body = "{}"
    })

if not response or
   response.StatusCode ~= 200 then

    warn("[LEXINX] BLOCK")
    return
end

local ok, data =
    pcall(function()

        return HttpService:JSONDecode(
            response.Body
        )

    end)

if not ok or
   type(data) ~= "table" or
   data.ok ~= true then

    warn("[LEXINX] Authentication failed")
    return
end

if data.version ~= VERSION then

    warn("[LEXINX] Version mismatch")
    return
end

print(
    "[LEXINX] Authorized"
)
`;

        res
            .status(200)
            .type("text/plain")
            .send(bootstrap);
    }
);


// ============================================================
// SESSION
// ============================================================

app.get(
    "/api/session",
    (req, res) => {

        return blocked(res);
    }
);


app.post(
    "/api/session",
    (req, res) => {

        // RATE LIMIT

        if (!checkRate(req)) {
            return blocked(res);
        }


        // CONTENT TYPE

        const contentType =
            req.headers[
                "content-type"
            ] || "";

        if (
            !contentType
                .toLowerCase()
                .startsWith(
                    "application/json"
                )
        ) {

            registerFailure(req);

            return blocked(res);
        }


        // HEADERS

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

            registerFailure(req);

            return blocked(res);
        }


        // VERSION

        if (
            version !== VERSION
        ) {

            registerFailure(req);

            return blocked(res);
        }


        // TIMESTAMP

        if (
            !/^\d{10}$/
                .test(timestamp)
        ) {

            registerFailure(req);

            return blocked(res);
        }

        const clientTime =
            Number(timestamp);

        if (
            !Number.isSafeInteger(
                clientTime
            )
        ) {

            registerFailure(req);

            return blocked(res);
        }

        if (
            Math.abs(
                unix() -
                clientTime
            ) > 30
        ) {

            registerFailure(req);

            return blocked(res);
        }


        // NONCE

        if (
            !validNonce(nonce)
        ) {

            registerFailure(req);

            return blocked(res);
        }


        // REPLAY

        if (
            nonces.has(nonce)
        ) {

            registerFailure(req);

            return blocked(res);
        }

        nonces.set(
            nonce,
            now()
        );


        // BODY

        if (
            !req.body ||
            typeof req.body !==
                "object" ||
            Array.isArray(
                req.body
            ) ||
            Object.keys(
                req.body
            ).length !== 0
        ) {

            registerFailure(req);

            return blocked(res);
        }


        // ====================================================
        // SESSION
        // ====================================================

        const session =
            crypto
                .randomBytes(32)
                .toString("hex");

        sessions.set(
            session,
            {
                created: now(),

                expires:
                    now() +
                    SESSION_TTL,

                version: VERSION
            }
        );


        // ====================================================
        // REAL JSON PAYLOAD
        // ====================================================

        return res
            .status(200)
            .json({

                ok: true,

                version: VERSION,

                session: session,

                expiresIn:
                    SESSION_TTL,

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
// SESSION CONFIG
// ============================================================

app.post(
    "/api/config",
    (req, res) => {

        if (!checkRate(req)) {
            return blocked(res);
        }

        const session =
            req.header(
                "X-Session"
            );

        if (
            typeof session !==
            "string"
        ) {

            registerFailure(req);

            return blocked(res);
        }

        const data =
            sessions.get(
                session
            );

        if (!data) {

            registerFailure(req);

            return blocked(res);
        }

        if (
            data.expires <
            now()
        ) {

            sessions.delete(
                session
            );

            return blocked(res);
        }

        if (
            data.version !==
            VERSION
        ) {

            return blocked(res);
        }

        return res.json({

            ok: true,

            version: VERSION,

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
// CLEANUP
// ============================================================

setInterval(() => {

    const current =
        now();

    for (
        const [
            nonce,
            created
        ] of nonces
    ) {

        if (
            current -
            created >
            NONCE_TTL
        ) {

            nonces.delete(
                nonce
            );
        }
    }

    for (
        const [
            session,
            data
        ] of sessions
    ) {

        if (
            data.expires <
            current
        ) {

            sessions.delete(
                session
            );
        }
    }

}, 30_000);


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

app.listen(
    PORT,
    () => {

        console.log(
            `[LEXINX ${VERSION}] ONLINE`
        );
    }
);
