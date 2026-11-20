local capture=...
_LIFTING=true
local prototypes={}
local function decode(root,reader,name)
    _PROTOTYPE=name
    local h=table.pack(reader(root,nil,true,capture.key))
    _ROOTCONSTANTS=h[1]
    local read,size,context=h[9],h[10],h[12]
    local _,_,_,init=read(0)
    init(h[4],{})
    local rows={}
    local children={}
    local proto={rows=rows,size=size,parameters=h[4],registers=h[5],vararg=h[6],header={h[4],h[5],h[6],h[7],h[8],h[10]}}
    prototypes[name]=proto
    local pc,opcode,a,b,c,resolve,ticket,masked,mask=1
    local nextpc,reading=1,false
    context[1]=function()return pc,opcode,a,b,c,masked,0,nextpc,reading end
    local pending={1}
    local paths={}
    local path={}
    local visited={}
    while #pending>0 do
        local offset=table.remove(pending)
        if visited[offset] or offset<1 or offset>size then continue end
        if paths[offset] then
            local saved=paths[offset]
            pcall(h[11],h[13])
            h=table.pack(reader(root,nil,true,capture.key))
            _ROOTCONSTANTS=h[1]
            read,size,context=h[9],h[10],h[12]
            local _,_,_,init=read(0);init(h[4],{})
            pc,opcode,a,b,c,masked,mask=1,nil,nil,nil,nil,nil,nil
            nextpc,reading=1,false
            context[1]=function()return pc,opcode,a,b,c,masked,0,nextpc,reading end
            path={}
            for _,replay in saved do
                nextpc,reading=replay,true
                opcode,a,b,c,resolve,ticket,masked,mask=read(replay,true)
                pc,nextpc,reading=replay,replay+_WIDTH(replay),false
                if masked then a,b,c=a-mask,b-mask,c-mask end
                local raw=resolve(ticket,1,{})
                masked=raw[1];a,b,c=raw[2]-mask,raw[3]-mask,raw[4]-mask
                path[#path+1]=replay
            end
            paths[offset]=nil
        end
        visited[offset]=true
        nextpc,reading=offset,true
        local result=table.pack(pcall(read,offset,true))
        if not result[1] then proto.error=tostring(result[2]);proto.error_pc=offset;proto.previous_pc=pc;break end
        opcode,a,b,c,resolve,ticket,masked,mask=table.unpack(result,2,result.n)
        pc,nextpc,reading=offset,offset+_WIDTH(offset),false
        if masked then a,b,c=a-mask,b-mask,c-mask end
        local ok,raw=pcall(resolve,ticket,1,{})
        if not ok then proto.error=tostring(raw);break end
        local shift=capture.metadata[opcode][1]
        masked=raw[1]
        a,b,c=raw[2]-mask,raw[3]-mask,raw[4]-mask
        local aa,bb,cc=a-shift,b-shift,c-shift
        local row={pc=pc,opcode=opcode,a=aa,b=bb,c=cc,width=_WIDTH(offset)}
        row.words=raw[5]
        _WORDS=raw[5]
        local ok,tuples=pcall(resolve,ticket,1,{_tuples=true})
        row.tuples=ok and tuples or tostring(tuples)
        _TUPLES=ok and tuples or nil
        rows[#rows+1]=row
        path[#path+1]=offset
        local state={false,false,{}, {},function()error("Application access blocked")end,nextpc,0,{},0}
        state._capture=true;state[12]=capture.constantContext
        local ok,value=pcall(resolve,ticket,1,state)
        if not ok then row.frame_error=tostring(value) end
        local targets={offset+row.width}
        if opcode==228 then
            nextpc=nextpc+bb*4
            row.jump_target=nextpc
            targets={nextpc}
        elseif opcode==1 or opcode==183 then targets={offset+4,offset+8}
        elseif opcode==53 then targets={offset+4+(aa~=0 and 4 or 0)}
        elseif opcode==25 then targets={offset+32,offset-4}
        elseif opcode==119 then targets={offset+32,offset-56}
        elseif opcode==159 then targets={offset+16,offset-60}
        elseif opcode==203 then targets={offset+76,offset+128}
        elseif opcode==157 then targets={offset+32,offset+84}
        elseif opcode==128 then targets={offset+48}
        elseif opcode==171 then targets={offset-56}
        elseif opcode==14 then targets={offset+12,offset+16}
        elseif opcode==112 then targets={offset-20}
        elseif opcode==113 then targets={offset-52}
        elseif opcode==125 then targets={offset-88}
        elseif opcode==149 then targets={offset-84}
        elseif opcode==161 then targets={offset-80}
        elseif opcode==160 then
            local ok,child=pcall(function()return h[3][cc+1]end)
            row.child_index=cc
            if ok then
                local childname=name.."_"..pc
                row.child=childname
                local parentupvalues=setmetatable({},{__index=function(_,index)return {upvalue=index-1}end})
                local bound,captures=pcall(child[2],nil,parentupvalues,nil,function(index)return {register=index-1}end)
                row.captures={}
                if bound then
                    for i,capture in _CAPTURES or {} do
                        row.captures[i]=capture[1]==1 and {register=capture[2]} or {upvalue=capture[2]}
                    end
                else row.capture_error=tostring(captures) end
                children[#children+1]={root=child[1],reader=child[3] or reader,name=childname}
            else row.child_error=tostring(child) end
        elseif opcode==97 or opcode==163 then
            row.terminates=true
            targets={}
        end
        row.successors=targets
        for i=#targets,1,-1 do
            local target=targets[i]
            if not visited[target] and target>=1 and target<=size then
                pending[#pending+1]=target
                if i>1 then paths[target]=table.clone(path) end
            end
        end
    end
    for _,child in children do
        local ok,err=pcall(decode,child.root,child.reader,child.name)
        if not ok then prototypes[child.name]={error=tostring(err)}end
    end
    return proto
end
decode(capture.root,capture.reader,"root")
local predicate={}
for _,value in {"nil","boolean","number","string","table","function","thread","userdata","abcdefgh","Function"}do
    local ok,result=pcall(capture.predicate,value,1)
    if ok then predicate[value]=result else predicate[value]=tostring(result) end
end
return {prototypes=prototypes,status="analysis",predicate=predicate}
