--[[
Project Gaai: one app to control the Nexxtender chargers.
Copyright © 2025, Frank HJ Cuypers

This program is free software: you can redistribute it and/or modify it under the terms of the
GNU Affero General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program.
If not, see <http://www.gnu.org/licenses/>.
--]] 

print("fuut.lua start")

-------------------------------------------------------------------------------
-- Lua Wireshark Dissector for Nexxtender charger BLE
-------------------------------------------------------------------------------
-- See https://github.com/FrankHJCuypers/Gaai/wiki/Nexxtender-Charger-Information
-------------------------------------------------------------------------------
-- Nexxtender charger profile
-------------------------------------------------------------------------------


-------------------------------------------------------------------------------
-- Charging Service
-------------------------------------------------------------------------------
local p_nexxt_charging = Proto("nexxt_charge_s", "Nexxtender Charging Service")

function p_nexxt_charging.dissector(buf, pinfo, tree)
	print("p_nexxt_charging.dissector")
end

-------------------------------------------------------------------------------
-- Charging Basic Data Characteristic
-------------------------------------------------------------------------------
print("fuut.lua defining Charging Basic Data")

local p_nexxt_cbd = Proto("nexxt_cbd", "Nexxtender Charging Basic Data")

local f_cbd_seconds = ProtoField.uint16("cbd.seconds", "Seconds", base.DEC)

local discriminatorValues = {
	[1] = "Started",
	[2] = "Charging",
	[3] = "Stopped",
}
local f_cbd_discriminator = ProtoField.uint8("cbd.discriminator", "Discriminator", base.HEX, discriminatorValues)
local statusValues = {
	[0x42] = "Plugged",
	[0x43] = "Charging",
	[0x44] = "Charging",
	[0x45] = "Fault",
	[0x46] = "Fault",
}
local f_cbd_status = ProtoField.uint8("cbd.status", "Status", base.HEX, statusValues)
local f_cbd_rfu1 = ProtoField.uint32("cbd.rfu1", "Rfu1", base.HEX)
local f_cbd_energy = ProtoField.uint32("cbd.enery", "Energy", base.DEC)
local f_cbd_rfu2 = ProtoField.uint8("cbd.rfu2", "Rfu2", base.HEX)
local f_cbd_phasecount = ProtoField.uint8("cbd.phasecount", "Phasecount", base.DEC)

p_nexxt_cbd.fields =  {
	f_cbd_seconds,
	f_cbd_discriminator,
	f_cbd_status, 
	f_cbd_rfu1, 
	f_cbd_energy,
	f_cbd_rfu2, 
	f_cbd_phasecount
}

function p_nexxt_cbd.dissector(buf, pinfo, tree)
	print("p_nexxt_cbd.dissector: ", buf:bytes():tohex())
	length = buf:len()
	if length ~= 14 then return end
	pinfo.cols.protocol = p_nexxt_cbd.name
	local subtree = tree:add(p_nexxt_cbd, buf())
	subtree:add_packet_field(f_cbd_seconds, buf(0,2), ENC_LITTLE_ENDIAN, "s")
	subtree:add_le(f_cbd_discriminator, buf(2,1))
	subtree:add_le(f_cbd_status, buf(3,1))
	subtree:add_le(f_cbd_rfu1, buf(4,4))
	subtree:add_packet_field(f_cbd_energy, buf(8,4), ENC_LITTLE_ENDIAN, "Wh")
	subtree:add_le(f_cbd_rfu2, buf(12,1))
	subtree:add_le(f_cbd_phasecount, buf(13,1))
end

print("fuut.lua defined Charging Basic Data")

-------------------------------------------------------------------------------
-- Charging Grid Data Characteristic
-------------------------------------------------------------------------------
print("fuut.lua defining Charging Grid Data")
local p_nexxt_cgd = Proto("nexxt_cgd", "Nexxtender Charging Grid Data")

local f_cgd_timestamp = ProtoField.absolute_time("cgd.timestamp", "Timestamp", base.LOCAL)
local f_cgd_l1 = ProtoField.int16("cgd.l1", "L1", base.DEC)
local f_cgd_l2 = ProtoField.int16("cgd.l2", "L2", base.DEC)
local f_cgd_l3 = ProtoField.int16("cgd.l3", "L3", base.DEC)
local f_cgd_consumed = ProtoField.int16("cgd.consumed", "Consumed", base.DEC)
local f_cgd_interval = ProtoField.uint16("cgd.interval", "Interval", base.DEC)
local f_cgd_crc16 = ProtoField.uint16("cgd.interval", "crc", base.HEX)

p_nexxt_cgd.fields =  {
	f_cgd_timestamp,
	f_cgd_l1,
	f_cgd_l2, 
	f_cgd_l3, 
	f_cgd_consumed,
	f_cgd_interval, 
	f_cgd_crc16
}

function p_nexxt_cgd.dissector(buf, pinfo, tree)
	print("p_nexxt_cgd.dissector: ", buf:bytes():tohex())
	length = buf:len()
	if length ~= 16 then return end
	pinfo.cols.protocol = p_nexxt_cgd.name
	local subtree = tree:add(p_nexxt_cgd, buf())
	subtree:add_le(f_cgd_timestamp, buf(0,4))
	subtree:add_packet_field(f_cgd_l1, buf(4,2), ENC_LITTLE_ENDIAN, "dA")
	subtree:add_packet_field(f_cgd_l2, buf(6,2), ENC_LITTLE_ENDIAN, "dA")
	subtree:add_packet_field(f_cgd_l3, buf(8,2), ENC_LITTLE_ENDIAN, "dA")
	subtree:add_packet_field(f_cgd_consumed, buf(10,2), ENC_LITTLE_ENDIAN, "Wh")
	subtree:add_packet_field(f_cgd_interval, buf(12,2), ENC_LITTLE_ENDIAN, "s")
	subtree:add_le(f_cgd_crc16, buf(14,2))
end

print("fuut.lua defined Charging Grid Data")

-------------------------------------------------------------------------------
-- Charging Car Data Characteristic
-------------------------------------------------------------------------------
print("fuut.lua defining Charging Car Data")
local p_nexxt_ccd = Proto("nexxt_ccd", "Nexxtender Charging Car Data")

local f_ccd_timestamp = ProtoField.absolute_time("ccd.timestamp", "Timestamp", base.LOCAL)
local f_ccd_l1 = ProtoField.int16("ccd.l1", "L1", base.DEC)
local f_ccd_l2 = ProtoField.int16("ccd.l2", "L2", base.DEC)
local f_ccd_l3 = ProtoField.int16("ccd.l3", "L3", base.DEC)
local f_ccd_p1 = ProtoField.int16("ccd.p1", "P1", base.DEC)
local f_ccd_p2 = ProtoField.int16("ccd.p2", "P2", base.DEC)
local f_ccd_p3 = ProtoField.int16("ccd.p3", "P3", base.DEC)
local f_ccd_crc16 = ProtoField.uint16("ccd.interval", "crc", base.HEX)

p_nexxt_ccd.fields =  {
	f_ccd_timestamp,
	f_ccd_l1,
	f_ccd_l2, 
	f_ccd_l3, 
	f_ccd_p1,
	f_ccd_p2,
	f_ccd_p3,
	f_ccd_crc16
}

function p_nexxt_ccd.dissector(buf, pinfo, tree)
	print("p_nexxt_ccd.dissector: ", buf:bytes():tohex())
	length = buf:len()
	if length ~= 18 then return end
	pinfo.cols.protocol = p_nexxt_ccd.name
	local subtree = tree:add(p_nexxt_ccd, buf())
	subtree:add_le(f_ccd_timestamp, buf(0,4))
	subtree:add_packet_field(f_ccd_l1, buf(4,2), ENC_LITTLE_ENDIAN, "dA")
	subtree:add_packet_field(f_ccd_l2, buf(6,2), ENC_LITTLE_ENDIAN, "dA")
	subtree:add_packet_field(f_ccd_l3, buf(8,2), ENC_LITTLE_ENDIAN, "dA")
	subtree:add_packet_field(f_ccd_p1, buf(10,2), ENC_LITTLE_ENDIAN, "W")
	subtree:add_packet_field(f_ccd_p2, buf(12,2), ENC_LITTLE_ENDIAN, "W")
	subtree:add_packet_field(f_ccd_p3, buf(14,2), ENC_LITTLE_ENDIAN, "W")
	subtree:add_le(f_ccd_crc16, buf(16,2))
end

print("fuut.lua defined Charging Grid Data")

-------------------------------------------------------------------------------
-- Charging Advanced Data Characteristic
-------------------------------------------------------------------------------
print("fuut.lua defining Charging Advanced Data")
local p_nexxt_cad = Proto("nexxt_cad", "Nexxtender Charging Advanced Data")

local f_cad_timestamp = ProtoField.absolute_time("cad.timestamp", "Timestamp", base.LOCAL)
local f_cad_iAvailable = ProtoField.int16("cad.iAvailable", "iAvailable", base.DEC)
local f_cad_gridPower = ProtoField.int32("cad.gridPower", "GridPower", base.DEC)
local f_cad_carPower = ProtoField.int32("cad.carPower", "CarPower", base.DEC)
local authorizationStatusValues = {
	[0x01] = "Unauthorized",
	[0x02] = "Authorized default",
	[0x22] = "Authorized MAX",
	[0x42] = "Authorized ECO",
}
local f_cad_authorizationStatus = ProtoField.uint8("cad.authorizationStatus", "AuthorizarionStatus", base.HEX, authorizationStatusValues)
local f_cad_errorCode = ProtoField.uint8("cad.errorCode", "ErrorCode", base.HEX)
local f_cad_crc16 = ProtoField.uint16("ccd.interval", "crc", base.HEX)
p_nexxt_cad.fields =  {
	f_cad_timestamp,
	f_cad_iAvailable,
	f_cad_gridPower, 
	f_cad_carPower, 
	f_cad_authorizationStatus,
	f_cad_errorCode,
	f_cad_crc16
}

function p_nexxt_cad.dissector(buf, pinfo, tree)
	print("p_nexxt_cad.dissector: ", buf:bytes():tohex())
	length = buf:len()
	if length ~= 18 then return end
	pinfo.cols.protocol = p_nexxt_cad.name
	local subtree = tree:add(p_nexxt_cad, buf())
	subtree:add_le(f_cad_timestamp, buf(0,4))
	subtree:add_packet_field(f_cad_iAvailable, buf(4,2), ENC_LITTLE_ENDIAN, "A")
	subtree:add_packet_field(f_cad_gridPower, buf(6,4), ENC_LITTLE_ENDIAN, "W")
	subtree:add_packet_field(f_cad_carPower, buf(10,4), ENC_LITTLE_ENDIAN, "W")
	subtree:add_le(f_cad_authorizationStatus, buf(14,1))
	subtree:add_le(f_cad_errorCode, buf(15,1))
	subtree:add_le(f_ccd_crc16, buf(16,2))
end

print("fuut.lua defined Charging Advanced Data")

-------------------------------------------------------------------------------
-- Generic/CDR Service
-------------------------------------------------------------------------------
local p_nexxt_generic_cdr = Proto("nexxt_generic_cdr_s", "Nexxtender Generic/CDR Service")

function p_nexxt_generic_cdr.dissector(buf, pinfo, tree)
	print("p_nexxt_generic_cdr.dissector")
end

local genericOperationValues = {
	[0x00] = "Loader",
	[0x10] = "Event",
	[0x20] = "Metric",
	[0x30] = "Badge",
	[0x40] = "Time",
	[0x50] = "Config",
}

-------------------------------------------------------------------------------
-- Generic/CDR Generic Command Characteristic - loader
-------------------------------------------------------------------------------
local p_nexxt_gcl = Proto("nexxt_gcl", "Nexxtender Generic/CDR Command: Loader")

local loaderOperationValues = {
	[0x01] = "Start Charging Default",
	[0x02] = "Start Charging MAX",
	[0x03] = "Start Charging Auto",
	[0x04] = "Start Charging ECO",
	[0x06] = "Stop Charging",
}

local f_gcl_operationId =  ProtoField.uint8("gcl.operationId", "operationId", base.HEX, loaderOperationValues)
local f_gcl_operationType = ProtoField.uint8("gcl.operationType", "operationType", base.HEX, genericOperationValues)

p_nexxt_gcl.fields =  {
	f_gcl_operationId,
	f_gcl_operationType
}

function p_nexxt_gcl.dissector(buf, pinfo, tree)
	print("p_nexxt_cgl.dissector: ", buf:bytes():tohex())
	length = buf:len()
	if length ~= 2 then return end
	pinfo.cols.protocol = p_nexxt_gcl.name
	local subtree = tree:add(p_nexxt_gcl, buf())
	subtree:add_le(f_gcl_operationId, buf(0,1))
	subtree:add_le(f_gcl_operationType, buf(1,1))
end

-------------------------------------------------------------------------------
-- Generic/CDR Generic Command Characteristic - event
-------------------------------------------------------------------------------
local p_nexxt_gce = Proto("nexxt_gce", "Nexxtender Generic/CDR Command: Event")

local eventOperationValues = {
	[0x01] = "Next",
	[0x02] = "Update Status",
}

local f_gce_operationId =  ProtoField.uint8("gec.operationId", "operationId", base.HEX, eventOperationValues)
local f_gce_operationType = ProtoField.uint8("gce.operationType", "operationType", base.HEX, genericOperationValues)

p_nexxt_gce.fields =  {
	f_gce_operationId,
	f_gce_operationType
}

function p_nexxt_gce.dissector(buf, pinfo, tree)
	print("p_nexxt_cge.dissector: ", buf:bytes():tohex())
	length = buf:len()
	if length ~= 2 then return end
	pinfo.cols.protocol = p_nexxt_gce.name
	local subtree = tree:add(p_nexxt_gce, buf())
	subtree:add_le(f_gce_operationId, buf(0,1))
	subtree:add_le(f_gce_operationType, buf(1,1))
end

-------------------------------------------------------------------------------
-- Generic/CDR Generic Command Characteristic - metrics
-------------------------------------------------------------------------------
local p_nexxt_gcm = Proto("nexxt_gcm", "Nexxtender Generic/CDR Command: Metrics")

local metricsOperationValues = {
	[0x01] = "Next",
	[0x02] = "Update Status",
}

local f_gcm_operationId =  ProtoField.uint8("gcm.operationId", "operationId", base.HEX, metricsOperationValues)
local f_gcm_operationType = ProtoField.uint8("gcm.operationType", "operationType", base.HEX, genericOperationValues)

p_nexxt_gcm.fields =  {
	f_gcm_operationId,
	f_gcm_operationType
}

function p_nexxt_gcm.dissector(buf, pinfo, tree)
	print("p_nexxt_cgm.dissector: ", buf:bytes():tohex())
	length = buf:len()
	if length ~= 2 then return end
	pinfo.cols.protocol = p_nexxt_gcm.name
	local subtree = tree:add(p_nexxt_gcm, buf())
	subtree:add_le(f_gcm_operationId, buf(0,1))
	subtree:add_le(f_gcm_operationType, buf(1,1))
end

-------------------------------------------------------------------------------
-- Generic/CDR Generic Command Characteristic - badge
-------------------------------------------------------------------------------
local p_nexxt_gcb = Proto("nexxt_gcb", "Nexxtender Generic/CDR Command: Badge")

local badgeOperationValues = {
	[0x01] = "Add Badge Default",
	[0x02] = "Add Badge MAX",
	[0x04] = "Delete Badge",
	[0x05] = "List Start",
	[0x06] = "List Next",
}

local f_gcb_operationId =  ProtoField.uint8("gcb.operationId", "operationId", base.HEX, badgeOperationValues)
local f_gcb_operationType = ProtoField.uint8("gcb.operationType", "operationType", base.HEX, genericOperationValues)

p_nexxt_gcb.fields =  {
	f_gcb_operationId,
	f_gcb_operationType
}

function p_nexxt_gcb.dissector(buf, pinfo, tree)
	print("p_nexxt_cgb.dissector: ", buf:bytes():tohex())
	length = buf:len()
	if length ~= 2 then return end
	pinfo.cols.protocol = p_nexxt_gcb.name
	local subtree = tree:add(p_nexxt_gcb, buf())
	subtree:add_le(f_gcb_operationId, buf(0,1))
	subtree:add_le(f_gcb_operationType, buf(1,1))
end

-------------------------------------------------------------------------------
-- Generic/CDR Generic Command Characteristic - time
-------------------------------------------------------------------------------
local p_nexxt_gct = Proto("nexxt_gct", "Nexxtender Generic/CDR Command: Time")

local timeOperationValues = {
	[0x01] = "Set",
	[0x02] = "Get",
}


local f_gct_operationId =  ProtoField.uint8("gct.operationId", "operationId", base.HEX, timeOperationValues)
local f_gct_operationType = ProtoField.uint8("gct.operationType", "operationType", base.HEX, genericOperationValues)

p_nexxt_gct.fields =  {
	f_gct_operationId,
	f_gct_operationType
}

function p_nexxt_gct.dissector(buf, pinfo, tree)
	print("p_nexxt_cgt.dissector: ", buf:bytes():tohex())
	length = buf:len()
	if length ~= 2 then return end
	pinfo.cols.protocol = p_nexxt_gct.name
	local subtree = tree:add(p_nexxt_gct, buf())
	subtree:add_le(f_gct_operationId, buf(0,1))
	subtree:add_le(f_gct_operationType, buf(1,1))
end

-------------------------------------------------------------------------------
-- Generic/CDR Generic Command Characteristic - config
-------------------------------------------------------------------------------
local p_nexxt_gcc = Proto("nexxt_gcc", "Nexxtender Generic/CDR Command: Configuration")

local configOperationValues = {
	[0x01] = "Set",
	[0x02] = "Get",
	[0x03] = "CBOR Set",
	[0x04] = "CBOR Get",
}

local f_gcc_operationId =  ProtoField.uint8("gcc.operationId", "operationId", base.HEX, configOperationValues)
local f_gcc_operationType = ProtoField.uint8("gcc.operationType", "operationType", base.HEX, genericOperationValues)

p_nexxt_gcc.fields =  {
	f_gcc_operationId,
	f_gcc_operationType
}

function p_nexxt_gcc.dissector(buf, pinfo, tree)
	print("p_nexxt_cgc.dissector: ", buf:bytes():tohex())
	length = buf:len()
	if length ~= 2 then return end
	pinfo.cols.protocol = p_nexxt_gcc.name
	local subtree = tree:add(p_nexxt_gcc, buf())
	subtree:add_le(f_gcc_operationId, buf(0,1))
	subtree:add_le(f_gcc_operationType, buf(1,1))
end

-------------------------------------------------------------------------------
-- Generic/CDR Generic Command Characteristic
-------------------------------------------------------------------------------
local p_nexxt_gc = Proto("nexxt_gc", "Nexxtender Generic/CDR Command")

local gcDissectors = {
	[0x00] = p_nexxt_gcl.dissector,
	[0x10] = p_nexxt_gce.dissector,
	[0x20] = p_nexxt_gcm.dissector,
	[0x30] = p_nexxt_gcb.dissector,
	[0x40] = p_nexxt_gct.dissector,
	[0x50] = p_nexxt_gcc.dissector,
}

print("fuut.lua defining Generic/CDR Generic Command")

function p_nexxt_gc.dissector(buf, pinfo, tree)
	print("p_nexxt_gc.dissector: ", buf:bytes():tohex())
	length = buf:len()
	if length ~= 2 then return end
	pinfo.cols.protocol = p_nexxt_gc.name
	local operationType=buf(1,1):uint()
	local dissector = gcDissectors[operationType]
	
	if dissector ~= nil then
		dissector:call(buf, pinfo, tree)
	end
end

-------------------------------------------------------------------------------
-- Generic/CDR Generic STATUS Characteristic - loader
-------------------------------------------------------------------------------
local p_nexxt_gsl = Proto("nexxt_gsl", "Nexxtender Generic/CDR Status: Loader")

local loaderStatusValues = {
	[0x01] = "Unlocked",
	[0x02] = "Unlocked Force MAX",
	[0x03] = "Unlocked Force ECO",
}

local f_gsl_operationStatus =  ProtoField.uint8("gsl.operationStatus", "operationStatus", base.HEX, loaderStatusValues)
local f_gsl_operationType = ProtoField.uint8("gsl.operationType", "operationType", base.HEX, genericOperationValues)

p_nexxt_gsl.fields =  {
	f_gsl_operationStatus,
	f_gsl_operationType
}

function p_nexxt_gsl.dissector(buf, pinfo, tree)
	print("p_nexxt_gsl.dissector: ", buf:bytes():tohex())
	length = buf:len()
	if length ~= 2 then return end
	pinfo.cols.protocol = p_nexxt_gsl.name
	local subtree = tree:add(p_nexxt_gsl, buf())
	subtree:add_le(f_gsl_operationStatus, buf(0,1))
	subtree:add_le(f_gsl_operationType, buf(1,1))
end

-------------------------------------------------------------------------------
-- Generic/CDR Generic STATUS Characteristic - event
-------------------------------------------------------------------------------
local p_nexxt_gse = Proto("nexxt_gse", "Nexxtender Generic/CDR Status: Event")


local f_gse_remainingEvents =  ProtoField.uint8("gse.remainingEvents", "remainingEvents", base.HEX)
local f_gse_operationType = ProtoField.uint8("gse.operationType", "operationType", base.HEX, genericOperationValues)

p_nexxt_gse.fields =  {
	f_gse_remainingEvents,
	f_gse_operationType
}

function p_nexxt_gse.dissector(buf, pinfo, tree)
	print("p_nexxt_gse.dissector: ", buf:bytes():tohex())
	length = buf:len()
	if length ~= 2 then return end
	pinfo.cols.protocol = p_nexxt_gse.name
	local subtree = tree:add(p_nexxt_gse, buf())
	subtree:add_le(f_gse_remainingEvents, buf(0,1))
	subtree:add_le(f_gse_operationType, buf(1,1))
end

-------------------------------------------------------------------------------
-- Generic/CDR Generic STATUS Characteristic - metric
-------------------------------------------------------------------------------
local p_nexxt_gsm = Proto("nexxt_gsm", "Nexxtender Generic/CDR Status: Metric")


local f_gsm_remainingEvents =  ProtoField.uint8("gsm.remainingEvents", "remainingEvents", base.HEX)
local f_gsm_operationType = ProtoField.uint8("gsm.operationType", "operationType", base.HEX, genericOperationValues)

p_nexxt_gsm.fields =  {
	f_gsm_remainingEvents,
	f_gsm_operationType
}

function p_nexxt_gsm.dissector(buf, pinfo, tree)
	print("p_nexxt_gsm.dissector: ", buf:bytes():tohex())
	length = buf:len()
	if length ~= 2 then return end
	pinfo.cols.protocol = p_nexxt_gsm.name
	local subtree = tree:add(p_nexxt_gsm, buf())
	subtree:add_le(f_gsm_remainingEvents, buf(0,1))
	subtree:add_le(f_gsm_operationType, buf(1,1))
end

-------------------------------------------------------------------------------
-- Generic/CDR Generic STATUS Characteristic - badge
-------------------------------------------------------------------------------
local p_nexxt_gsb = Proto("nexxt_gsb", "Nexxtender Generic/CDR Status: Badge")

local badgeStatusValues = {
	[0x01] = "Wait Add",
	[0x02] = "Wait Add",
	[0x04] = "Wait Delete",
	[0x05] = "Next",
	[0x07] = "Finish",
	[0x08] = "Added",
	[0x09] = "Exists",
}

local f_gsb_operationStatus =  ProtoField.uint8("gsb.operationStatus", "operationStatus", base.HEX, badgeStatusValues)
local f_gsb_operationType = ProtoField.uint8("gsb.operationType", "operationType", base.HEX, genericOperationValues)

p_nexxt_gsb.fields =  {
	f_gsb_operationStatus,
	f_gsb_operationType
}

function p_nexxt_gsb.dissector(buf, pinfo, tree)
	print("p_nexxt_gsb.dissector: ", buf:bytes():tohex())
	length = buf:len()
	if length ~= 2 then return end
	pinfo.cols.protocol = p_nexxt_gsb.name
	local subtree = tree:add(p_nexxt_gsb, buf())
	subtree:add_le(f_gsb_operationStatus, buf(0,1))
	subtree:add_le(f_gsb_operationType, buf(1,1))
end

-------------------------------------------------------------------------------
-- Generic/CDR Generic STATUS Characteristic - time
-------------------------------------------------------------------------------
local p_nexxt_gst = Proto("nexxt_gst", "Nexxtender Generic/CDR Status: Time")

local timeStatusValues = {
	[0x01] = "Ready",
	[0x02] = "Success",
	[0x03] = "Popped",
}

local f_gst_operationStatus =  ProtoField.uint8("gst.operationStatus", "operationStatus", base.HEX, timeStatusValues)
local f_gst_operationType = ProtoField.uint8("gst.operationType", "operationType", base.HEX, genericOperationValues)

p_nexxt_gst.fields =  {
	f_gst_operationStatus,
	f_gst_operationType
}

function p_nexxt_gst.dissector(buf, pinfo, tree)
	print("p_nexxt_gst.dissector: ", buf:bytes():tohex())
	length = buf:len()
	if length ~= 2 then return end
	pinfo.cols.protocol = p_nexxt_gst.name
	local subtree = tree:add(p_nexxt_gst, buf())
	subtree:add_le(f_gst_operationStatus, buf(0,1))
	subtree:add_le(f_gst_operationType, buf(1,1))
end

-------------------------------------------------------------------------------
-- Generic/CDR Generic STATUS Characteristic - config
-------------------------------------------------------------------------------
local p_nexxt_gsc = Proto("nexxt_gsc", "Nexxtender Generic/CDR Status: Config")

local configStatusValues = {
	[0x01] = "Ready (After a Config Set)",
	[0x02] = "Success (After a Config Set)",
	[0x03] = "Popped (After a Config Get)",
	[0x04] = "Ready (After a Config CBOR Set)",
	[0x05] = "Success (After a Config CBOR Set)",
	[0x06] = "Popped (After a Config CBOR Get)",
}

local f_gsc_operationStatus =  ProtoField.uint8("gsc.operationStatus", "operationStatus", base.HEX, configStatusValues)
local f_gsc_operationType = ProtoField.uint8("gsc.operationType", "operationType", base.HEX, genericOperationValues)

p_nexxt_gsc.fields =  {
	f_gsc_operationStatus,
	f_gsc_operationType
}

function p_nexxt_gsc.dissector(buf, pinfo, tree)
	print("p_nexxt_gsc.dissector: ", buf:bytes():tohex())
	length = buf:len()
	if length ~= 2 then return end
	pinfo.cols.protocol = p_nexxt_gsc.name
	local subtree = tree:add(p_nexxt_gsc, buf())
	subtree:add_le(f_gsc_operationStatus, buf(0,1))
	subtree:add_le(f_gsc_operationType, buf(1,1))
end

-------------------------------------------------------------------------------
-- Generic/CDR Generic STATUS Characteristic
-------------------------------------------------------------------------------
local p_nexxt_gs = Proto("nexxt_gs", "Nexxtender Generic/CDR Status")

local gsDissectors = {
	[0x00] = p_nexxt_gsl.dissector,
	[0x10] = p_nexxt_gse.dissector,
	[0x20] = p_nexxt_gsm.dissector,
	[0x30] = p_nexxt_gsb.dissector,
	[0x40] = p_nexxt_gst.dissector,
	[0x50] = p_nexxt_gsc.dissector,
}

print("fuut.lua defining Generic/CDR Generic Status")

function p_nexxt_gs.dissector(buf, pinfo, tree)
	print("p_nexxt_gs.dissector: ", buf:bytes():tohex())
	length = buf:len()
	if length ~= 2 then return end
	pinfo.cols.protocol = p_nexxt_gs.name
	local operationType=buf(1,1):uint()
	local dissector = gsDissectors[operationType]
	
	if dissector ~= nil then
		dissector:call(buf, pinfo, tree)
	end
end


print("fuut.lua defined Generic/CDR Generic Command")


-------------------------------------------------------------------------------
-- Registering all dissectors
-------------------------------------------------------------------------------
print("fuut.lua registering dissectors")

local UUID_NEXXTENDER_BASE = "fd47416a-95fb-4206-88b5-b4a8045f75"
local UUID_NEXXTENDER_CHARGING_SERVICE = UUID_NEXXTENDER_BASE.."c1"
local UUID_NEXXTENDER_CHARGING_BASIC_DATA_CHARACTERISTIC = UUID_NEXXTENDER_BASE.."cf"
local UUID_NEXXTENDER_CHARGING_GRID_DATA_CHARACTERISTIC = UUID_NEXXTENDER_BASE.."d0"
local UUID_NEXXTENDER_CHARGING_CAR_DATA_CHARACTERISTIC = UUID_NEXXTENDER_BASE.."da"
local UUID_NEXXTENDER_CHARGING_ADVANCED_DATA_CHARACTERISTIC = UUID_NEXXTENDER_BASE.."db"
local UUID_NEXXTENDER_GENERIC_COMMAND_CHARACTERISTIC = UUID_NEXXTENDER_BASE.."dd"
local UUID_NEXXTENDER_GENERIC_STATUS_CHARACTERISTIC = UUID_NEXXTENDER_BASE.."de"

local p_nexxt = Proto("nexxt", "Nexxtender BLE GATT")


local bt_dissector = DissectorTable.get("bluetooth.uuid")

print("fuut.lua registering dissector p_nexxt_charging ")
bt_dissector:add(UUID_NEXXTENDER_CHARGING_SERVICE, p_nexxt_charging)
print("fuut.lua registering dissector p_nexxt_cbd ")
bt_dissector:add(UUID_NEXXTENDER_CHARGING_BASIC_DATA_CHARACTERISTIC, p_nexxt_cbd)
print("fuut.lua registering dissector p_nexxt_cgd ")
bt_dissector:add(UUID_NEXXTENDER_CHARGING_GRID_DATA_CHARACTERISTIC, p_nexxt_cgd)
print("fuut.lua registering dissector p_nexxt_ccd ")
bt_dissector:add(UUID_NEXXTENDER_CHARGING_CAR_DATA_CHARACTERISTIC, p_nexxt_ccd)
print("fuut.lua registering dissector p_nexxt_cad ")
bt_dissector:add(UUID_NEXXTENDER_CHARGING_ADVANCED_DATA_CHARACTERISTIC, p_nexxt_cad)
print("fuut.lua registering dissector p_nexxt_gc ")
bt_dissector:add(UUID_NEXXTENDER_GENERIC_COMMAND_CHARACTERISTIC, p_nexxt_gc)
print("fuut.lua registering dissector p_nexxt_gs ")
bt_dissector:add(UUID_NEXXTENDER_GENERIC_STATUS_CHARACTERISTIC, p_nexxt_gs)


print("fuut.lua end")
