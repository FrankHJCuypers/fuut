local p_btatt_wrapper = Proto("btatt_wrapper", "btatt wrapper test")

local f_btatt_wrapper_activated1 = ProtoField.bool("btatt_wrapper.activated1", "Wrapper 1 activated?")
local f_btatt_wrapper_activated2 = ProtoField.bool("btatt_wrapper.activated2", "Wrapper 2 activated?")

p_btatt_wrapper.fields = {
    f_btatt_wrapper_activated1,
    f_btatt_wrapper_activated2,
}

local original_btatt_dissector_cid

function p_btatt_wrapper.dissector(buf, pinfo, tree)
	return original_btatt_dissector_cid:call(buf, pinfo, tree)
end

local btatt_dissector_table_cid = DissectorTable.get("btl2cap.cid")
original_btatt_dissector_cid = btatt_dissector_table_cid:get_dissector(0x0004) -- BTL2CAP_FIXED_CID_ATT       
btatt_dissector_table_cid:add(0x0004, p_btatt_wrapper)
