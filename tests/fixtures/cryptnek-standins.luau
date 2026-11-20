local events, callbacks, jobs = {}, {}, {}
local function record(...)
    local values = table.pack(...)
    for i = 1, values.n do
        if type(values[i]) == "function" then values[i] = "<callback>" end
        values[i] = tostring(values[i])
    end
    events[#events + 1] = table.concat(values, "|")
end
local folder = {}
function folder:AddList(options)
    record("list", options.text, table.concat(options.values, ","))
    callbacks[#callbacks + 1] = {kind="list", callback=options.callback, values=options.values}
    return folder
end
function folder:AddButton(options)
    record("button", options.text)
    callbacks[#callbacks + 1] = {kind="button", callback=options.callback}
    return folder
end
function folder:AddLabel(options)
    record("label", options.text)
    local properties = {Text=options.text}
    return setmetatable({}, {__index=properties, __newindex=function(_, key, value) record("label-property", key, value); properties[key]=value end})
end
function folder:AddValue(value) record("add", value) end
function folder:RemoveValue(value) record("remove", value) end
local window = {}
function window:AddFolder(text) record("folder", text); return folder end
function window:Init() record("init") end
local library = {}
function library:CreateWindow(text) record("window", text); return window end
function library:Init() record("init") end
function loadstring(source)
    assert(source == "local fixture module", "Unexpected source evaluation")
    return function() return library end
end
local env = getfenv()
function getgenv() return env end
function setclipboard(text) record("clipboard", text) end
CFrame = {new=function(...) record("cframe", ...); return "fixture-cframe", nil, "extra" end}
local character = {PivotTo=function(self, ...) record("pivot", ...) end}
local total = {Text="42"}
game = {
    HttpGet=function(self, url) record("http", url); return "local fixture module" end,
    Players={LocalPlayer={Character=character, PlayerGui={JinxPoints={JinxPointsGuiPane={PointsMount={Face={Content={Total=total}}}}}}}}
}
workspace = {Ingredients={GetChildren=function() return {} end, FindFirstChild=function() return nil end}}
function workspace:FindFirstChild(name) record("find", name); return self[name] end
local waitsRemaining = 1
task = {
    spawn=function(callback) jobs[#jobs + 1] = callback; record("spawn") end,
    wait=function(seconds)
        record("wait", seconds)
        if waitsRemaining == 0 then error("fixture-yield", 0) end
        waitsRemaining -= 1
        return seconds
    end
}
function wait(seconds) return task.wait(seconds) end
function typeof(value) return type(value) end
return {events=events, callbacks=callbacks, jobs=jobs, setBudget=function(count) waitsRemaining=count end, snapshot=function() return table.concat(events, "\n") end}
