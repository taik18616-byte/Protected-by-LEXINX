const \u0065\u0078\u0070\u0072\u0065\u0073\u0073 = require("express");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

const TOKEN =
    process.env.LEXINX_TOKEN || "\u0043\u0048\u0041\u004e\u0047\u0045\u005f\u004d\u0045";

const PAYLOAD = String.raw`
local \u0050\u006c\u0061\u0079\u0065\u0072\u0073 = game:GetService("Players")
local \u0048\u0074\u0074\u0070\u0053\u0065\u0072\u0076\u0069\u0063\u0065 = game:GetService("HttpService")

local API =
    "\u0068\u0074\u0074\u0070\u0073\u003a\u002f\u002f\u006c\u0033\u0078\u0069\u006e\u0078\u002d\u0061\u0070\u0069\u002e\u006f\u006e\u0072\u0065\u006e\u0064\u0065\u0072\u002e\u0063\u006f\u006d\u002f\u0061\u0070\u0069\u002f\u0073\u006f\u0075\u006e\u0064"

local TOKEN =
    "\u0043\u0048\u0041\u004e\u0047\u0045\u005f\u004d\u0045"

local function nonce()
    local chars =
        "\u0061\u0062\u0063\u0064\u0065\u0066\u0067\u0068\u0069\u006a\u006b\u006c\u006d\u006e\u006f\u0070\u0071\u0072\u0073\u0074\u0075\u0076\u0077\u0078\u0079\u007a\u0041\u0042\u0043\u0044\u0045\u0046\u0047\u0048\u0049\u004a\u004b\u004c\u004d\u004e\u004f\u0050\u0051\u0052\u0053\u0054\u0055\u0056\u0057\u0058\u0059\u005a\u0030\u0031\u0032\u0033\u0034\u0035\u0036\u0037\u0038\u0039"

    local result = \u007b\u007d

    for i = 1, 32 do
        local n =
            math.random(1, #chars)

        result[i] =
            chars:sub(n, n)
    end

    return \u0074\u0061\u0062\u006c\u0065.concat(result)
end

local ok, response =
    pcall(function()

        return request({
            Url = API,
            Method = "\u0050\u004f\u0053\u0054",

            Headers = {
                ["\u0043\u006f\u006e\u0074\u0065\u006e\u0074\u002d\u0054\u0079\u0070\u0065"] =
                    "\u0061\u0070\u0070\u006c\u0069\u0063\u0061\u0074\u0069\u006f\u006e\u002f\u006a\u0073\u006f\u006e",

                ["\u0058\u002d\u0054\u006f\u006b\u0065\u006e"] =
                    TOKEN,

                ["\u0058\u002d\u0054\u0069\u006d\u0065"] =
                    to\u0073\u0074\u0072\u0069\u006e\u0067(os.time()),

                ["\u0058\u002d\u004e\u006f\u006e\u0063\u0065"] =
                    nonce()
            },

            Body = "{}"
        })

    end)

if not ok or
   not response or
   response.StatusCode ~= 200 then

    warn("\u004c\u0045\u0058\u0049\u004e\u0058\u0020\u0042\u004c\u004f\u0043\u004b")
    return
end

local su\u0063\u0063ess, data =
    pcall(function()

        return HttpService:JSONDecode(
            response.Body
        )

    end)

if not success or
   type(data) ~= "table" or
   data.ok ~= true then

    warn("\u0041\u0075\u0074\u0068\u0065\u006e\u0074\u0069\u0063\u0061\u0074\u0069\u006f\u006e\u0020\u0066\u0061\u0069\u006c\u0065\u0064")
    return
end

local player =
    Players.LocalPlayer

local character =
    player.Character
    or player.CharacterAdded:Wait()

local root =
    character:WaitForChild(
        "\u0048\u0075\u006d\u0061\u006e\u006f\u0069\u0064\u0052\u006f\u006f\u0074\u0050\u0061\u0072\u0074"
    )

local sound =
    Instance.new("\u0053\u006f\u0075\u006e\u0064")

sound.SoundId =
    "\u0072\u0062\u0078\u0061\u0073\u0073\u0065\u0074\u0069\u0064\u003a\u002f\u002f"
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


\u002f/ ======================================
// PUBLIC HOME
// ======================================

app.get("/", (req, res) => {
    res.type("\u0074\u0065\u0078\u0074").send("cc");
});


// ======================================
// PAYLOAD
// ======================================

app.get(
    "\u002f\u0061\u0070\u0069\u002f\u0038\u0032\u0037\u0065\u0038\u0032\u006a\u0078\u0038\u0032\u0038\u0032\u0038\u0032\u006a\u0073",
    (req, res) => {

        res
            .type("\u0074\u0065\u0078\u0074\u002f\u0070\u006c\u0061\u0069\u006e")
            .send(PAYLOAD);
    }
);


// ======================================
// SOUND API
// ======================================

const usedNonces =
    new Map();

app.post(
    "\u002f\u0061\u0070\u0069\u002f\u0073\u006f\u0075\u006e\u0064",
    (req, res) => {

        const token =
            req.header("\u0058\u002d\u0054\u006f\u006b\u0065\u006e");

        const timestamp =
            Number(req.header("\u0058\u002d\u0054\u0069\u006d\u0065"));

        const nonce =
            req.header("\u0058\u002d\u004e\u006f\u006e\u0063\u0065");


        // TOKEN
        if (token !== TOKEN) {

            return res
                .status(403)
                .json({
                    ok: false,
                    error: "\u0042\u004c\u004f\u0043\u004b\u0045\u0044"
                });
        }


        // TIMESTAMP
        if (!timestamp) {

            return res
                .status(400)
                .json({
                    ok: false,
                    error: "\u0049\u004e\u0056\u0041\u004c\u0049\u0044\u005f\u0054\u0049\u004d\u0045"
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
                    error: "\u0045\u0058\u0050\u0049\u0052\u0045\u0044"
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
                    error: "\u0049\u004e\u0056\u0041\u004c\u0049\u0044\u005f\u004e\u004f\u004e\u0043\u0045"
                });
        }


        // \u0052\u0045\u0050\u004c\u0041\u0059
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

            version: "\u0056\u0035\u0030",

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
            .type("\u0074\u0065\u0078\u0074")
            .send(
                "\u0042\u006c\u006f\u0063\u006b\u0065\u0064\u0020\u0062\u0079\u0020\u004c\u0045\u0058\u0049\u004e\u0058\u0020\u0076\u0035\u0030\u0020\u0070\u0072\u006f\u0074\u0065\u0063\u0074\u0069\u006f\u006e"
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
            "\u004c\u0045\u0058\u0049\u004e\u0058\u0020\u0056\u0035\u0030\u0020\u0041\u0050\u0049\u0020\u006f\u006e\u006c\u0069\u006e\u0065"
        );
    }
);
