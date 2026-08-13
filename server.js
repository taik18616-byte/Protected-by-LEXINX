const express = require("express");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

const TOKEN =
    process.env.LEXINX_TOKEN || "CHANCE_ME";

const PAYLOAD = String.raw`
local Players = game:GetService("Players")
local HttpService = game:GetService("HttpService")

local API =
    "https://l3xinx-api.onrender.com/api/sound"

local TOKEN =
    "CHANGE_ME"

local function nonce()
    local chars =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    local result = {}

    for i = 1, 32 do
        local n =
            math.random(1, #chars)

        result[i] =
            chars:sub(n, n)
    end

    return table.concat(result)
end

local ok, response =
    pcall(function()

        return request({
            Url = API,
            Method = "POST",

            Headers = {
                ["Content-Type"] =
                    "application/json",

                ["X-Token"] =
                    TOKEN,

                ["X-Time"] =
                    tostring(os.time()),

                ["X-Nonce"] =
                    nonce()
            },

            Body = "{}"
        })

    end)

if not ok or
   not response or
   response.StatusCode ~= 200 then

    warn("LEXINX BLOCK")
    return
end

local success, data =
    pcall(function()

        return HttpService:JSONDecode(
            response.Body
        )

    end)

if not success or
   type(data) ~= "table" or
   data.ok ~= true then

    warn("Authentication failed")
    return
end

local player =
    Players.LocalPlayer

local character =
    player.Character
    or player.CharacterAdded:Wait()

local root =
    character:WaitForChild(
        "HumanoidRootPart"
    )

local sound =
    Instance.new("Sound")

sound.SoundId =
    "rbxassetid://"
    .. tostring(data.soundId)

sound.Volume =
    tonumber(data.volume) or 4

sound.PlaybackSpeed =
    tonumber(data.speed) or 0.2

sound.Parent =
    root

sound:Play()

sound.Ended:Once(function()
    sound:Destroy()
end)
`;


// ======================================
// PUBLIC HOME
// ======================================

app.get("/", (req, res) => {
    res.type("text").send("cc");
});


// ======================================
// PAYLOAD
// ======================================

app.get(
    "/api/827e82jx828282js",
    (req, res) => {

        res
            .type("text/plain")
            .send(PAYLOAD);
    }
);


// ======================================
// SOUND API
// ======================================

const usedNonces =
    new Map();

app.post(
    "/api/sound",
    (req, res) => {

        const token =
            req.header("X-Token");

        const timestamp =
            Number(req.header("X-Time"));

        const nonce =
            req.header("X-Nonce");


        // TOKEN
        if (token !== TOKEN) {

            return res
                .status(403)
                .json({
                    ok: false,
                    error: "BLOCKED"
                });
        }


        // TIMESTAMP
        if (!timestamp) {

            return res
                .status(400)
                .json({
                    ok: false,
                    error: "INVALID_TIME"
                });
        }


        const now =
            Math.floor(
                Date.now() / 1000
            );


        if (
            Math.abs(
                now - timestamp
            ) > 60
        ) {

            return res
                .status(401)
                .json({
                    ok: false,
                    error: "EXPIRED"
                });
        }


        // NONCE
        if (
            typeof nonce !== "string" ||
            nonce.length < 16
        ) {

            return res
                .status(400)
                .json({
                    ok: false,
                    error: "INVALID_NONCE"
                });
        }


        // REPLAY
        if (
            usedNonces.has(nonce)
        ) {

            return res
                .status(409)
                .json({
                    ok: false,
                    error: "REPLAY"
                });
        }


        usedNonces.set(
            nonce,
            Date.now()
        );


        // PAYLOAD DATA
        res.json({
            ok: true,

            version: "V50",

            soundId:
                132545213997354,

            volume:
                4,

            speed:
                0.2
        });
    }
);


// ======================================
// CLEANUP NONCES
// ======================================

setInterval(() => {

    const now =
        Date.now();

    for (
        const [
            nonce,
            time
        ] of usedNonces
    ) {

        if (
            now - time >
            120000
        ) {

            usedNonces.delete(
                nonce
            );
        }
    }

}, 30000);


// ======================================
// BLOCK UNKNOWN ROUTES
// ======================================

app.use(
    (req, res) => {

        res
            .status(403)
            .type("text")
            .send(
                "Blocked by LEXINX v50 protection"
            );
    }
);


// ======================================
// START
// ======================================

app.listen(
    PORT,
    () => {

        console.log(
            "LEXINX V50 API online"
        );
    }
);
