--[[
Small dissector that demonstrates Wireshark issue 20537 
Support long_attribute_value for proprietary 128-bit UUIDs BTGATT attribute values](https://gitlab.com/wireshark/wireshark/-/issues/20537)
reported in [Reassemble CDR Record packets](https://github.com/FrankHJCuypers/fuut/issues/1).

The same dissector() is registered for UUID 2a28 and fd47416a-95fb-4206-88b5-b4a8045f75c4.
The dissector just prints the incoming buf:len().
For 2a28 it print 27, proving the dissector was triggered after reassembling the 2 parts (22+5).
For fd47416a-95fb-4206-88b5-b4a8045f75c48 it prints 22, 
proving the dissector was triggered after receiving the first packet (22 bytes) and not after reassembling 32 bytes (22+10).
--]]

-- Dissector for fd47416a-95fb-4206-88b5-b4a8045f75c4
local p_nexxt_cdrr = Proto("nexxt_cdrr", "Nexxtender CDR Record")

function p_nexxt_cdrr.dissector(buf, pinfo, tree)
	print("p_nexxt_cdrr.dissector #bytes: "..buf:len())
end

local UUID_NEXXTENDER_BASE = "fd47416a-95fb-4206-88b5-b4a8045f75"
local UUID_NEXXTENDER_CDR_RECORD_CHARACTERISTIC = UUID_NEXXTENDER_BASE .. "c4"
local bt_dissector = DissectorTable.get("bluetooth.uuid")
bt_dissector:add(UUID_NEXXTENDER_CDR_RECORD_CHARACTERISTIC, p_nexxt_cdrr)


-- Dissector for UUID 0x2a28
local p_srs = Proto("srs", "Software Revision String")

function p_srs.dissector(buf, pinfo, tree)
	print("p_srs.dissector #bytes: "..buf:len())
end

bt_dissector:add("2a28", p_srs)
