--[[
    Author: WDissectorGen
    Language: Lua
    Date: 2019-02-07
    Description: Wireshark Dissector for myprotocol
]]--

myprotocol = Proto("myprotocol", "myprotocol Protocol")

-- Fields Declaration Section
sequence_counter_field=ProtoField.uint32("myprotocol.sequence_counter_field","Sequence Counter",base.DEC)
type_field=ProtoField.uint16("myprotocol.type_field","Type",base.HEX)
checksum_field=ProtoField.uint8("myprotocol.checksum_field","Checksum",base.HEX)
name_field=ProtoField.string("myprotocol.name_field","Name",base.NONE)

myprotocol.fields = {
    sequence_counter_field,
type_field,
checksum_field,
name_field
}

-- Dissector Callback Declaration
function myprotocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    -- Adds protocol name to protocol column
    pinfo.cols.protocol = myprotocol.name
    
    -- Creates the subtree
    local subtree = tree:add(myprotocol, buffer(),"myprotocol Protocol Data")

    -- Local Variables Declaration
    local sequence_counter = buffer(0,4)
local type = buffer(4,2)
local checksum = buffer(6,1)
local name = buffer(7,7)

    -- Adds Variables to the subtree
    subtree:add(sequence_counter_field, sequence_counter)
subtree:add(type_field, type)
subtree:add(checksum_field, checksum)
subtree:add(name_field, name):append_text("[hide_vocals():".. hide_vocals(name).."]")
end

function hide_vocals(value)
   local edited = value:bytes()
   local converted = ""
   edited:set_index(0,0x21)
   edited:set_index(3,0x21)
   edited:set_index(5,0x21)
   edited:set_index(6,0x21)
   for i=0,6 do 
      converted = converted .. string.char(edited:get_index(i)) 
   end
   return converted
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(8888, myprotocol)
