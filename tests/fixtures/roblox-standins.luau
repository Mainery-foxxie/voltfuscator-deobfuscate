-- Local stand-ins only: no Roblox client, network, or external module execution.
local options = ...
local events = {buttons={}, quests={}, purchases={}, printed={}, warned={}, notifications={}, clipboard={}, waits={}}
local player = {Name="FixturePlayer"}
local remote = {}
function remote:IsA(className)
    assert(className == "RemoteFunction")
    return true
end
function remote:InvokeServer(...)
    local args = table.pack(...)
    assert(args.n == 4, "Quest invocation lost its self argument or values")
    events.quests[#events.quests+1] = args
    if options.questFailAt == #events.quests then error("fixture quest failure", 0) end
    return "accepted"
end
local replicatedStorage = {}
function replicatedStorage:WaitForChild(name)
    assert(name == "fixture-md5", "Incorrect quest remote name")
    return remote
end
local cryptography = {}
function cryptography.MD5(value)
    assert(value == "ObjectivesReporter_ReportProgressFunc" .. (options.jobId == "" and "00000000-0000-0000-0000-000000000000" or options.jobId))
    return "fixture-md5"
end
local ugc = {}
function ugc.BuyUGC(...)
    local args = table.pack(...)
    assert(args.n == 3 and args[1] == player and type(args[2]) == "string" and args[3] == false, "Incorrect UGC call arguments")
    events.purchases[#events.purchases+1] = args
    if options.purchaseFails then error("fixture purchase failure", 0) end
    return "bought", nil, 42
end
local ui = {}
function ui:NewWindow(title)
    assert(title == "Anime Monster Collector")
    return self
end
function ui:SetFooter(text, icon, style)
    assert(text == "Dc: https://discord.gg/qgV6v9WcE9" and icon == 128337196312757 and style == 1)
end
function ui:NewSection(title)
    assert(title == "Main" or title == "Credits")
    return self
end
function ui:CreateButton(title, callback)
    assert(type(callback) == "function")
    assert(events.buttons[title] == nil)
    events.buttons[title] = callback
end
function ui:SendNotification(...)
    local args = table.pack(...)
    assert(args.n == 6 and args[1] == "Copied!" and args[3] == 2 and args[5] == 1)
    if args[2] == "YouTube link copied to clipboard!" then
        assert(args[4] == 108320733835485 and args[6] == "red")
    else
        assert(args[2] == "Discord invite copied to clipboard!" and args[4] == 119731774091515 and args[6] == "blue")
    end
    events.notifications[#events.notifications+1] = args
end
workspace = {Lib={TGSMisc={Cryptography=cryptography}, UGC={TGSLimitedUGCV2=ugc}}}
game = {JobId=options.jobId}
function game:GetService(name)
    if name == "Workspace" then return workspace end
    if name == "Players" then return {LocalPlayer=player} end
    assert(name == "ReplicatedStorage")
    return replicatedStorage
end
function game:HttpGet(url)
    assert(url == "https://raw.githubusercontent.com/oxireun/UiLibrary/refs/heads/main/2049.lua")
    return "fixture-ui-source"
end
function require(module)
    assert(module == cryptography or module == ugc)
    return module
end
function loadstring(source)
    assert(source == "fixture-ui-source")
    return function() return ui end
end
function print(...) events.printed[#events.printed+1] = table.pack(...) end
function warn(...) events.warned[#events.warned+1] = table.pack(...) end
task = {wait=function(seconds)
    assert(seconds == 0.1)
    events.waits[#events.waits+1] = seconds
end}
if options.clipboardEnabled then
    function setclipboard(value) events.clipboard[#events.clipboard+1] = value end
end
return events
