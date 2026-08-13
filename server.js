const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;

const PAYLOAD = String.raw`
local Players = game:GetService("Players")
local HttpService = game:GetService("HttpService")

local API =
    "https://l3xinx-api.onrender.com/api/sound"

local TOKEN = "LEXINX_V50_8f91c2a84d0e5b31"

local function nonce()
    local chars =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    local result = {}

    for i = 1, 32 do
        local n = math.random(1, #chars)
        result[i] = chars:sub(n, n)
    end

    return table.concat(result)
end

local response = request({
    Url = API,
    Method = "POST",

    Headers = {
        ["Content-Type"] = "application/json",
        ["X-Token"] = TOKEN,
        ["X-Time"] = tostring(os.time()),
        ["X-Nonce"] = nonce()
    },

    Body = "{}"
})

if not response or response.StatusCode ~= 200 then
    warn("LEXINX BLOCK")
    return
end

local success, data =
    pcall(function()
        return HttpService:JSONDecode(response.Body)
    end)

if not success or not data.ok then
    warn("Authentication failed")
    return
end

local player = Players.LocalPlayer

local character =
    player.Character or player.CharacterAdded:Wait()

local root =
    character:WaitForChild("HumanoidRootPart")

local sound = Instance.new("Sound")

sound.SoundId =
    "rbxassetid://" .. tostring(data.soundId)

sound.Volume =
    data.volume

sound.PlaybackSpeed =
    data.speed

sound.Parent = root
sound:Play()

sound.Ended:Once(function()
    sound:Destroy()
end)
`;

app.get("/", (req, res) => {
    res.type("text").send("cc");
});

app.get("/api/827e82jx828282js", (req, res) => {
    res.type("text/plain").send(PAYLOAD);
});

app.listen(PORT, () => {
    console.log("LEXINX API running on port " + PORT);
});
