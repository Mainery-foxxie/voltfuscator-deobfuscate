local capture = ...
local header = table.pack(capture.reader(capture.root, nil, true, capture.key))
_ROOTCONSTANTS=header[1]
local read, size, context = header[9], header[10], header[12]
local pc, opcode, a, b, c, resolve, ticket, masked, mask = 1
local regs,upvalues,_,initialize=read(0)
initialize(header[4],{})
local nextpc, reading = 1, false
local shift = 0
local rows = {}
local offset = 1
while offset <= size do
    nextpc, reading = offset, true
    local result = table.pack(pcall(read, offset, true))
    if not result[1] then
        rows[#rows+1] = {pc=offset, error=tostring(result[2])}
        break
    end
    opcode, a, b, c, resolve, ticket, masked, mask = table.unpack(result,2,result.n)
    shift = capture.shifts[opcode] or 0
    if masked then a, b, c = a - mask - shift, b - mask - shift, c - mask - shift end
    pc, nextpc, reading = offset, offset + _WIDTH(offset), false
    context[1] = function() return pc, opcode, (a or 0)+shift, (b or 0)+shift, (c or 0)+shift, masked, 0, nextpc, reading end
    local row = {pc=pc, opcode=opcode, a=a, b=b, c=c, masked=masked, mask=mask}
    local ok, result = pcall(resolve,ticket,1,{})
    if ok then
        row.raw_operands = result
        if type(result)=="table" and type(result[2])=="number" then
            local second_shift=capture.metadata[opcode][1]
            row.a,row.b,row.c=result[2]-second_shift,result[3]-second_shift,result[4]-second_shift
        end
    else row.operand_error=tostring(result) end
    rows[#rows+1] = row
    do
        local state={false,false,{}, {},function() error("Application access blocked") end,nextpc,0,{},0}
        state._capture=true
        state[12]=capture.constantContext
        local ok,err=pcall(resolve,ticket,1,state)
        if not ok then row.frame_error=tostring(err)
        elseif err==nil then row.unresolved="compound handler"
        end
    end
    offset = nextpc
end
return rows
