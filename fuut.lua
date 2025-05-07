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
-- CRC-16-MODBUS
-- Also known as CRC-16-IBM, Bisync, USB, ANSI X3.28, SIA DC-07,...
-- Not the fastest implementation, but simple
-------------------------------------------------------------------------------
local polynomial = 0x8005
local initial_value = 0xFFFF

local function crc16_modbus(data, start, len)
    local crc = 0xFFFF
    for i = start, start + len - 1 do
        local b = data:get_index(i)
        crc = crc ~ b
        for j = 1, 8 do
            if (crc & 0x0001) == 1 then
                crc = (crc >> 1) ~ 0xA001
            else
                crc = crc >> 1
            end
        end
    end
    return crc
end

local function crc16_modbus_alternative(data, start, len)
    local crc = 0xFFFF
    for i = start, start + len - 1 do
        local b = data:get_index(i)
        for j = 0, 7 do
            local bit = (b >> j) & 0x0001
            local c15 = (crc >> 15) & 0x0001
            crc = (crc << 1) & 0xFFFF
            if ((c15 ~ bit) & 0x0001) == 1 then
                crc = crc ~ 0x8005
            end
        end
    end

    return ((crc << 8) & 0xFFFF) | (crc >> 8)
end

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
    [3] = "Stopped"
}
local f_cbd_discriminator = ProtoField.uint8("cbd.discriminator", "Discriminator", base.HEX, discriminatorValues)
local statusValues = {
    [0x42] = "Plugged",
    [0x43] = "Charging",
    [0x44] = "Charging",
    [0x45] = "Fault",
    [0x46] = "Fault"
}
local f_cbd_status = ProtoField.uint8("cbd.status", "Status", base.HEX, statusValues)
local f_cbd_rfu1 = ProtoField.uint32("cbd.rfu1", "Rfu1", base.HEX)
local f_cbd_energy = ProtoField.uint32("cbd.enery", "Energy", base.DEC)
local f_cbd_rfu2 = ProtoField.uint8("cbd.rfu2", "Rfu2", base.HEX)
local f_cbd_phasecount = ProtoField.uint8("cbd.phasecount", "Phasecount", base.DEC)

p_nexxt_cbd.fields = {
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
    if length ~= 14 then
        return
    end
    pinfo.cols.protocol = p_nexxt_cbd.name
    local subtree = tree:add(p_nexxt_cbd, buf())
    subtree:add_packet_field(f_cbd_seconds, buf(0, 2), ENC_LITTLE_ENDIAN, "s")
    subtree:add_le(f_cbd_discriminator, buf(2, 1))
    subtree:add_le(f_cbd_status, buf(3, 1))
    subtree:add_le(f_cbd_rfu1, buf(4, 4))
    subtree:add_packet_field(f_cbd_energy, buf(8, 4), ENC_LITTLE_ENDIAN, "Wh")
    subtree:add_le(f_cbd_rfu2, buf(12, 1))
    subtree:add_le(f_cbd_phasecount, buf(13, 1))
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
local f_cgd_crc16 = ProtoField.uint16("cgd.crc16", "crc16", base.HEX)
local f_cgd_crcIncorrect =
    ProtoExpert.new("cgd.crc16.wrong", "CRC incorrect", expert.group.CHECKSUM, expert.severity.ERROR)
p_nexxt_cgd.fields = {
    f_cgd_timestamp,
    f_cgd_l1,
    f_cgd_l2,
    f_cgd_l3,
    f_cgd_consumed,
    f_cgd_interval,
    f_cgd_crc16
}

p_nexxt_cgd.experts = {
    f_cgd_crcIncorrect
}

function p_nexxt_cgd.dissector(buf, pinfo, tree)
    print("p_nexxt_cgd.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 16 then
        return
    end
    pinfo.cols.protocol = p_nexxt_cgd.name
    local subtree = tree:add(p_nexxt_cgd, buf())

    subtree:add_le(f_cgd_timestamp, buf(0, 4))
    subtree:add_packet_field(f_cgd_l1, buf(4, 2), ENC_LITTLE_ENDIAN, "dA")
    subtree:add_packet_field(f_cgd_l2, buf(6, 2), ENC_LITTLE_ENDIAN, "dA")
    subtree:add_packet_field(f_cgd_l3, buf(8, 2), ENC_LITTLE_ENDIAN, "dA")
    subtree:add_packet_field(f_cgd_consumed, buf(10, 2), ENC_LITTLE_ENDIAN, "Wh")
    subtree:add_packet_field(f_cgd_interval, buf(12, 2), ENC_LITTLE_ENDIAN, "s")
    local treeitem = subtree:add_le(f_cgd_crc16, buf(14, 2))

    local computedCrc = crc16_modbus(buf:bytes(), 0, 14)
    local receivedCrc = buf:bytes(14, 2):le_uint()
    print("Computed crc: " .. string.format("0x%04x", computedCrc))
    if (receivedCrc ~= computedCrc) then
        treeitem:add_proto_expert_info(f_cgd_crcIncorrect, string.format("Expected CRC value 0x%04x", computedCrc))
    end
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
local f_ccd_crc16 = ProtoField.uint16("ccd.crc16", "crc16", base.HEX)
local f_ccd_crcIncorrect =
    ProtoExpert.new("ccd.crc16.wrong", "CRC incorrect", expert.group.CHECKSUM, expert.severity.ERROR)

p_nexxt_ccd.fields = {
    f_ccd_timestamp,
    f_ccd_l1,
    f_ccd_l2,
    f_ccd_l3,
    f_ccd_p1,
    f_ccd_p2,
    f_ccd_p3,
    f_ccd_crc16
}

p_nexxt_ccd.experts = {
    f_ccd_crcIncorrect
}
function p_nexxt_ccd.dissector(buf, pinfo, tree)
    print("p_nexxt_ccd.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 18 then
        return
    end
    pinfo.cols.protocol = p_nexxt_ccd.name
    local subtree = tree:add(p_nexxt_ccd, buf())
    subtree:add_le(f_ccd_timestamp, buf(0, 4))
    subtree:add_packet_field(f_ccd_l1, buf(4, 2), ENC_LITTLE_ENDIAN, "dA")
    subtree:add_packet_field(f_ccd_l2, buf(6, 2), ENC_LITTLE_ENDIAN, "dA")
    subtree:add_packet_field(f_ccd_l3, buf(8, 2), ENC_LITTLE_ENDIAN, "dA")
    subtree:add_packet_field(f_ccd_p1, buf(10, 2), ENC_LITTLE_ENDIAN, "W")
    subtree:add_packet_field(f_ccd_p2, buf(12, 2), ENC_LITTLE_ENDIAN, "W")
    subtree:add_packet_field(f_ccd_p3, buf(14, 2), ENC_LITTLE_ENDIAN, "W")
    local treeitem = subtree:add_le(f_ccd_crc16, buf(16, 2))

    local computedCrc = crc16_modbus(buf:bytes(), 0, 16)
    local receivedCrc = buf:bytes(16, 2):le_uint()
    print("Computed crc: " .. string.format("0x%04x", computedCrc))
    if (receivedCrc ~= computedCrc) then
        treeitem:add_proto_expert_info(f_ccd_crcIncorrect, string.format("Expected CRC value 0x%04x", computedCrc))
    end
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
    [0x42] = "Authorized ECO"
}
local f_cad_authorizationStatus =
    ProtoField.uint8("cad.authorizationStatus", "AuthorizarionStatus", base.HEX, authorizationStatusValues)
local f_cad_errorCode = ProtoField.uint8("cad.errorCode", "ErrorCode", base.HEX)
local f_cad_crc16 = ProtoField.uint16("cad.crc16", "crc", base.HEX)
local f_cad_crcIncorrect =
    ProtoExpert.new("cad.crc16.wrong", "CRC incorrect", expert.group.CHECKSUM, expert.severity.ERROR)
p_nexxt_cad.fields = {
    f_cad_timestamp,
    f_cad_iAvailable,
    f_cad_gridPower,
    f_cad_carPower,
    f_cad_authorizationStatus,
    f_cad_errorCode,
    f_cad_crc16
}

p_nexxt_cad.experts = {
    f_cad_crcIncorrect
}

function p_nexxt_cad.dissector(buf, pinfo, tree)
    print("p_nexxt_cad.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 18 then
        return
    end
    pinfo.cols.protocol = p_nexxt_cad.name
    local subtree = tree:add(p_nexxt_cad, buf())
    subtree:add_le(f_cad_timestamp, buf(0, 4))
    subtree:add_packet_field(f_cad_iAvailable, buf(4, 2), ENC_LITTLE_ENDIAN, "A")
    subtree:add_packet_field(f_cad_gridPower, buf(6, 4), ENC_LITTLE_ENDIAN, "W")
    subtree:add_packet_field(f_cad_carPower, buf(10, 4), ENC_LITTLE_ENDIAN, "W")
    subtree:add_le(f_cad_authorizationStatus, buf(14, 1))
    subtree:add_le(f_cad_errorCode, buf(15, 1))
    local treeitem = subtree:add_le(f_ccd_crc16, buf(16, 2))

    local computedCrc = crc16_modbus(buf:bytes(), 0, 16)
    local receivedCrc = buf:bytes(16, 2):le_uint()
    print("Computed crc: " .. string.format("0x%04x", computedCrc))
    if (receivedCrc ~= computedCrc) then
        treeitem:add_proto_expert_info(f_cad_crcIncorrect, string.format("Expected CRC value 0x%04x", computedCrc))
    end
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
    [0x50] = "Config"
}

-- In order to know how to parse a Generic Data message,
-- we need to know which Generic Command was send before, or at least its operation type.
-- g_genericOperationTypeOnLine is populated with the operation type for each
-- packet number containing a Generic Command or Generic Status command.
-- That way, when a packet needs to know the last operation type, it can lookup the table.
-- g_genericOperationTypeOnLine is not sorted.
-- g_genericOperationTypeOnLineSorted is used to sort according to packet number.
-- See https://www.lua.org/pil/19.3.html for the algorithm.
local g_genericOperationTypeOnLine = {}
local g_genericOperationTypeOnLineSorted = {}

function AddGenericOperationType(number, operationType)
    print("AddGenericOperationType number, operationType", number, operationType)
    g_genericOperationTypeOnLine[number] = operationType
    SortGenericOperationType()
    Print_g_genericOperationTypeOnLine()
end

function SortGenericOperationType()
    print("SortGenericOperationType")
    g_genericOperationTypeOnLineSorted = {}
    for n in pairs(g_genericOperationTypeOnLine) do
        table.insert(g_genericOperationTypeOnLineSorted, n)
    end
    table.sort(g_genericOperationTypeOnLineSorted)
end

function GetLastOperationType(number)
    print("GetLastOperationType number:", number)

    local lastOperationTypeNumber = 0
    for i, pnum in ipairs(g_genericOperationTypeOnLineSorted) do
        if pnum < number then
            lastOperationTypeNumber = pnum
        end
    end

    local lastOperationType = g_genericOperationTypeOnLine[lastOperationTypeNumber]

    print("GetLastOperationType found:", lastOperationType)
    return lastOperationType
end

function Print_g_genericOperationTypeOnLine()
    local count = 0

    for k, v in pairs(g_genericOperationTypeOnLineSorted) do
        print(v .. " = " .. g_genericOperationTypeOnLine[v])
        count = count + 1
    end
    print("Print_g_genericOperationTypeOnLine found:", count)
    return count
end

-------------------------------------------------------------------------------
-- Generic Command Characteristic - loader
-------------------------------------------------------------------------------
local p_nexxt_gcl = Proto("nexxt_gcl", "Nexxtender Generic Command: Loader")

local loaderOperationValues = {
    [0x01] = "Start Charging Default",
    [0x02] = "Start Charging MAX",
    [0x03] = "Start Charging Auto",
    [0x04] = "Start Charging ECO",
    [0x06] = "Stop Charging"
}

local f_gcl_operationId = ProtoField.uint8("gcl.operationId", "OperationId", base.HEX, loaderOperationValues)
local f_gcl_operationType = ProtoField.uint8("gcl.operationType", "OperationType", base.HEX, genericOperationValues)

p_nexxt_gcl.fields = {
    f_gcl_operationId,
    f_gcl_operationType
}

function p_nexxt_gcl.dissector(buf, pinfo, tree)
    print("p_nexxt_cgl.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 2 then
        return
    end
    pinfo.cols.protocol = p_nexxt_gcl.name
    local subtree = tree:add(p_nexxt_gcl, buf())
    subtree:add_le(f_gcl_operationId, buf(0, 1))
    subtree:add_le(f_gcl_operationType, buf(1, 1))
end

-------------------------------------------------------------------------------
-- Generic Command Characteristic - event
-------------------------------------------------------------------------------
local p_nexxt_gce = Proto("nexxt_gce", "Nexxtender Generic Command: Event")

local eventOperationValues = {
    [0x01] = "Next",
    [0x02] = "Update Status"
}

local f_gce_operationId = ProtoField.uint8("gec.operationId", "OperationId", base.HEX, eventOperationValues)
local f_gce_operationType = ProtoField.uint8("gce.operationType", "OperationType", base.HEX, genericOperationValues)

p_nexxt_gce.fields = {
    f_gce_operationId,
    f_gce_operationType
}

function p_nexxt_gce.dissector(buf, pinfo, tree)
    print("p_nexxt_cge.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 2 then
        return
    end
    pinfo.cols.protocol = p_nexxt_gce.name
    local subtree = tree:add(p_nexxt_gce, buf())
    subtree:add_le(f_gce_operationId, buf(0, 1))
    subtree:add_le(f_gce_operationType, buf(1, 1))
end

-------------------------------------------------------------------------------
-- Generic Command Characteristic - metrics
-------------------------------------------------------------------------------
local p_nexxt_gcm = Proto("nexxt_gcm", "Nexxtender Generic Command: Metrics")

local metricsOperationValues = {
    [0x01] = "Next",
    [0x02] = "Update Status"
}

local f_gcm_operationId = ProtoField.uint8("gcm.operationId", "OperationId", base.HEX, metricsOperationValues)
local f_gcm_operationType = ProtoField.uint8("gcm.operationType", "OperationType", base.HEX, genericOperationValues)

p_nexxt_gcm.fields = {
    f_gcm_operationId,
    f_gcm_operationType
}

function p_nexxt_gcm.dissector(buf, pinfo, tree)
    print("p_nexxt_cgm.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 2 then
        return
    end
    pinfo.cols.protocol = p_nexxt_gcm.name
    local subtree = tree:add(p_nexxt_gcm, buf())
    subtree:add_le(f_gcm_operationId, buf(0, 1))
    subtree:add_le(f_gcm_operationType, buf(1, 1))
end

-------------------------------------------------------------------------------
-- Generic Command Characteristic - badge
-------------------------------------------------------------------------------
local p_nexxt_gcb = Proto("nexxt_gcb", "Nexxtender Generic Command: Badge")

local badgeOperationValues = {
    [0x01] = "Add Badge Default",
    [0x02] = "Add Badge MAX",
    [0x04] = "Delete Badge",
    [0x05] = "List Start",
    [0x06] = "List Next"
}

local f_gcb_operationId = ProtoField.uint8("gcb.operationId", "OperationId", base.HEX, badgeOperationValues)
local f_gcb_operationType = ProtoField.uint8("gcb.operationType", "OperationType", base.HEX, genericOperationValues)

p_nexxt_gcb.fields = {
    f_gcb_operationId,
    f_gcb_operationType
}

function p_nexxt_gcb.dissector(buf, pinfo, tree)
    print("p_nexxt_cgb.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 2 then
        return
    end
    pinfo.cols.protocol = p_nexxt_gcb.name
    local subtree = tree:add(p_nexxt_gcb, buf())
    subtree:add_le(f_gcb_operationId, buf(0, 1))
    subtree:add_le(f_gcb_operationType, buf(1, 1))
end

-------------------------------------------------------------------------------
-- Generic Command Characteristic - time
-------------------------------------------------------------------------------
local p_nexxt_gct = Proto("nexxt_gct", "Nexxtender Generic Command: Time")

local timeOperationValues = {
    [0x01] = "Set",
    [0x02] = "Get"
}

local f_gct_operationId = ProtoField.uint8("gct.operationId", "OperationId", base.HEX, timeOperationValues)
local f_gct_operationType = ProtoField.uint8("gct.operationType", "OperationType", base.HEX, genericOperationValues)

p_nexxt_gct.fields = {
    f_gct_operationId,
    f_gct_operationType
}

function p_nexxt_gct.dissector(buf, pinfo, tree)
    print("p_nexxt_cgt.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 2 then
        return
    end
    pinfo.cols.protocol = p_nexxt_gct.name
    local subtree = tree:add(p_nexxt_gct, buf())
    subtree:add_le(f_gct_operationId, buf(0, 1))
    subtree:add_le(f_gct_operationType, buf(1, 1))
end

-------------------------------------------------------------------------------
-- Generic Command Characteristic - config
-------------------------------------------------------------------------------
local p_nexxt_gcc = Proto("nexxt_gcc", "Nexxtender Generic Command: Configuration")

local configOperationValues = {
    [0x01] = "Set",
    [0x02] = "Get",
    [0x03] = "CBOR Set",
    [0x04] = "CBOR Get"
}

local f_gcc_operationId = ProtoField.uint8("gcc.operationId", "OperationId", base.HEX, configOperationValues)
local f_gcc_operationType = ProtoField.uint8("gcc.operationType", "OperationType", base.HEX, genericOperationValues)

p_nexxt_gcc.fields = {
    f_gcc_operationId,
    f_gcc_operationType
}

function p_nexxt_gcc.dissector(buf, pinfo, tree)
    print("p_nexxt_cgc.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 2 then
        return
    end
    pinfo.cols.protocol = p_nexxt_gcc.name
    local subtree = tree:add(p_nexxt_gcc, buf())
    subtree:add_le(f_gcc_operationId, buf(0, 1))
    subtree:add_le(f_gcc_operationType, buf(1, 1))
end

-------------------------------------------------------------------------------
-- Generic Command Characteristic
-------------------------------------------------------------------------------
local p_nexxt_gc = Proto("nexxt_gc", "Nexxtender Generic Command")

local gcDissectors = {
    [0x00] = p_nexxt_gcl.dissector,
    [0x10] = p_nexxt_gce.dissector,
    [0x20] = p_nexxt_gcm.dissector,
    [0x30] = p_nexxt_gcb.dissector,
    [0x40] = p_nexxt_gct.dissector,
    [0x50] = p_nexxt_gcc.dissector
}

print("fuut.lua defining Generic Command")

function p_nexxt_gc.dissector(buf, pinfo, tree)
    print("p_nexxt_gc.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 2 then
        return
    end
    pinfo.cols.protocol = p_nexxt_gc.name
    local operationType = buf(1, 1):uint()
    AddGenericOperationType(pinfo.number, operationType)
    Print_g_genericOperationTypeOnLine()

    print("p_nexxt_gc.dissector sets operationType:", operationType, " for number ", pinfo.number)

    local dissector = gcDissectors[operationType]

    if dissector ~= nil then
        dissector:call(buf, pinfo, tree)
    end
end

-------------------------------------------------------------------------------
-- Generic STATUS Characteristic - loader
-------------------------------------------------------------------------------
local p_nexxt_gsl = Proto("nexxt_gsl", "Nexxtender Generic Status: Loader")

local loaderStatusValues = {
    [0x01] = "Unlocked",
    [0x02] = "Unlocked Force MAX",
    [0x03] = "Unlocked Force ECO"
}

local f_gsl_operationStatus = ProtoField.uint8("gsl.operationStatus", "OperationStatus", base.HEX, loaderStatusValues)
local f_gsl_operationType = ProtoField.uint8("gsl.operationType", "OperationType", base.HEX, genericOperationValues)

p_nexxt_gsl.fields = {
    f_gsl_operationStatus,
    f_gsl_operationType
}

function p_nexxt_gsl.dissector(buf, pinfo, tree)
    print("p_nexxt_gsl.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 2 then
        return
    end
    pinfo.cols.protocol = p_nexxt_gsl.name
    local subtree = tree:add(p_nexxt_gsl, buf())
    subtree:add_le(f_gsl_operationStatus, buf(0, 1))
    subtree:add_le(f_gsl_operationType, buf(1, 1))
end

-------------------------------------------------------------------------------
-- Generic STATUS Characteristic - event
-------------------------------------------------------------------------------
local p_nexxt_gse = Proto("nexxt_gse", "Nexxtender Generic Status: Event")

local f_gse_remainingEvents = ProtoField.uint8("gse.remainingEvents", "RemainingEvents", base.HEX)
local f_gse_operationType = ProtoField.uint8("gse.operationType", "OperationType", base.HEX, genericOperationValues)

p_nexxt_gse.fields = {
    f_gse_remainingEvents,
    f_gse_operationType
}

function p_nexxt_gse.dissector(buf, pinfo, tree)
    print("p_nexxt_gse.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 2 then
        return
    end
    pinfo.cols.protocol = p_nexxt_gse.name
    local subtree = tree:add(p_nexxt_gse, buf())
    subtree:add_le(f_gse_remainingEvents, buf(0, 1))
    subtree:add_le(f_gse_operationType, buf(1, 1))
end

-------------------------------------------------------------------------------
-- Generic STATUS Characteristic - metric
-------------------------------------------------------------------------------
local p_nexxt_gsm = Proto("nexxt_gsm", "Nexxtender Generic Status: Metric")

local f_gsm_remainingEvents = ProtoField.uint8("gsm.remainingEvents", "RemainingEvents", base.HEX)
local f_gsm_operationType = ProtoField.uint8("gsm.operationType", "OperationType", base.HEX, genericOperationValues)

p_nexxt_gsm.fields = {
    f_gsm_remainingEvents,
    f_gsm_operationType
}

function p_nexxt_gsm.dissector(buf, pinfo, tree)
    print("p_nexxt_gsm.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 2 then
        return
    end
    pinfo.cols.protocol = p_nexxt_gsm.name
    local subtree = tree:add(p_nexxt_gsm, buf())
    subtree:add_le(f_gsm_remainingEvents, buf(0, 1))
    subtree:add_le(f_gsm_operationType, buf(1, 1))
end

-------------------------------------------------------------------------------
-- Generic STATUS Characteristic - badge
-------------------------------------------------------------------------------
local p_nexxt_gsb = Proto("nexxt_gsb", "Nexxtender Generic Status: Badge")

local badgeStatusValues = {
    [0x01] = "Wait Add",
    [0x02] = "Wait Add",
    [0x04] = "Wait Delete",
    [0x05] = "Next",
    [0x07] = "Finish",
    [0x08] = "Added",
    [0x09] = "Exists"
}

local f_gsb_operationStatus = ProtoField.uint8("gsb.operationStatus", "OperationStatus", base.HEX, badgeStatusValues)
local f_gsb_operationType = ProtoField.uint8("gsb.operationType", "OperationType", base.HEX, genericOperationValues)

p_nexxt_gsb.fields = {
    f_gsb_operationStatus,
    f_gsb_operationType
}

function p_nexxt_gsb.dissector(buf, pinfo, tree)
    print("p_nexxt_gsb.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 2 then
        return
    end
    pinfo.cols.protocol = p_nexxt_gsb.name
    local subtree = tree:add(p_nexxt_gsb, buf())
    subtree:add_le(f_gsb_operationStatus, buf(0, 1))
    subtree:add_le(f_gsb_operationType, buf(1, 1))
end

-------------------------------------------------------------------------------
-- Generic STATUS Characteristic - time
-------------------------------------------------------------------------------
local p_nexxt_gst = Proto("nexxt_gst", "Nexxtender Generic Status: Time")

local timeStatusValues = {
    [0x01] = "Ready",
    [0x02] = "Success",
    [0x03] = "Popped"
}

local f_gst_operationStatus = ProtoField.uint8("gst.operationStatus", "OperationStatus", base.HEX, timeStatusValues)
local f_gst_operationType = ProtoField.uint8("gst.operationType", "OperationType", base.HEX, genericOperationValues)

p_nexxt_gst.fields = {
    f_gst_operationStatus,
    f_gst_operationType
}

function p_nexxt_gst.dissector(buf, pinfo, tree)
    print("p_nexxt_gst.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 2 then
        return
    end
    pinfo.cols.protocol = p_nexxt_gst.name
    local subtree = tree:add(p_nexxt_gst, buf())
    subtree:add_le(f_gst_operationStatus, buf(0, 1))
    subtree:add_le(f_gst_operationType, buf(1, 1))
end

-------------------------------------------------------------------------------
-- Generic STATUS Characteristic - config
-------------------------------------------------------------------------------
local p_nexxt_gsc = Proto("nexxt_gsc", "Nexxtender Generic Status: Config")

local configStatusValues = {
    [0x01] = "Ready (After a Config Set)",
    [0x02] = "Success (After a Config Set)",
    [0x03] = "Popped (After a Config Get)",
    [0x04] = "Ready (After a Config CBOR Set)",
    [0x05] = "Success (After a Config CBOR Set)",
    [0x06] = "Popped (After a Config CBOR Get)"
}

local f_gsc_operationStatus = ProtoField.uint8("gsc.operationStatus", "OperationStatus", base.HEX, configStatusValues)
local f_gsc_operationType = ProtoField.uint8("gsc.operationType", "OperationType", base.HEX, genericOperationValues)

p_nexxt_gsc.fields = {
    f_gsc_operationStatus,
    f_gsc_operationType
}

function p_nexxt_gsc.dissector(buf, pinfo, tree)
    print("p_nexxt_gsc.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 2 then
        return
    end
    pinfo.cols.protocol = p_nexxt_gsc.name
    local subtree = tree:add(p_nexxt_gsc, buf())
    subtree:add_le(f_gsc_operationStatus, buf(0, 1))
    subtree:add_le(f_gsc_operationType, buf(1, 1))
end

-------------------------------------------------------------------------------
-- Generic STATUS Characteristic
-------------------------------------------------------------------------------
local p_nexxt_gs = Proto("nexxt_gs", "Nexxtender Generic Status")

local gsDissectors = {
    [0x00] = p_nexxt_gsl.dissector,
    [0x10] = p_nexxt_gse.dissector,
    [0x20] = p_nexxt_gsm.dissector,
    [0x30] = p_nexxt_gsb.dissector,
    [0x40] = p_nexxt_gst.dissector,
    [0x50] = p_nexxt_gsc.dissector
}

print("fuut.lua defining Generic Generic Status")

function p_nexxt_gs.dissector(buf, pinfo, tree)
    print("p_nexxt_gs.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 2 then
        return
    end
    pinfo.cols.protocol = p_nexxt_gs.name
    local operationType = buf(1, 1):uint()
    AddGenericOperationType(pinfo.number, operationType)
    Print_g_genericOperationTypeOnLine()

    print("p_nexxt_gs.dissector sets operationType:", operationType, " for number ", pinfo.number)
    local dissector = gsDissectors[operationType]

    if dissector ~= nil then
        dissector:call(buf, pinfo, tree)
    end
end

-------------------------------------------------------------------------------
-- Generic DATA Characteristic - loader
-------------------------------------------------------------------------------
local p_nexxt_gdl = Proto("nexxt_gdl", "Nexxtender Generic Data: Loader")

function p_nexxt_gdl.dissector(buf, pinfo, tree)
    print("p_nexxt_gdl.dissector: ", buf:bytes():tohex())
    -- nothing: there are no Generic Data Characteristics for the Loader
end

-------------------------------------------------------------------------------
-- Generic Data Characteristic - event
-------------------------------------------------------------------------------
local p_nexxt_gde = Proto("nexxt_gde", "Nexxtender Generic Data: Event")

local f_gde_eventTime = ProtoField.absolute_time("gde.EventTime", "EventTime", base.LOCAL)
local f_gde_unknown1 = ProtoField.uint8("gsd.unknown1", "Unknown1", base.HEX)
local f_gde_unknown2 = ProtoField.uint8("gsd.unknown2", "Unknown2", base.HEX)
local f_gde_unknown3 = ProtoField.uint8("gsd.unknown3", "Unknown3", base.HEX)
local f_gde_data = ProtoField.bytes("gsd.data", "Data")
local f_gde_crc16 = ProtoField.uint16("gde.crc16", "crc16", base.HEX)

local f_gde_crcIncorrect =
    ProtoExpert.new("gde.crc16.wrong", "CRC incorrect", expert.group.CHECKSUM, expert.severity.ERROR)

p_nexxt_gde.fields = {
    f_gde_eventTime,
    f_gde_unknown1,
    f_gde_unknown2,
    f_gde_unknown3,
    f_gde_data,
    f_gde_crc16
}

p_nexxt_gde.experts = {
    f_gde_crcIncorrect
}

function p_nexxt_gde.dissector(buf, pinfo, tree)
    print("p_nexxt_gde.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 20 then
        return
    end
    pinfo.cols.protocol = p_nexxt_gde.name
    local subtree = tree:add(p_nexxt_gde, buf())
    subtree:add_le(f_gde_eventTime, buf(0, 4))
    subtree:add_le(f_gde_unknown1, buf(4, 1))
    subtree:add_le(f_gde_unknown2, buf(5, 1))
    subtree:add_le(f_gde_unknown3, buf(6, 1))
    subtree:add_le(f_gde_data, buf(7, 11))
    local treeitem = subtree:add_le(f_gde_crc16, buf(18, 2))
    local computedCrc = crc16_modbus(buf:bytes(), 0, 18)
    local receivedCrc = buf:bytes(18, 2):le_uint()
    print("Computed crc: " .. string.format("0x%04x", computedCrc))
    if (receivedCrc ~= computedCrc) then
        treeitem:add_proto_expert_info(f_gde_crcIncorrect, string.format("Expected CRC value 0x%04x", computedCrc))
    end
end

-------------------------------------------------------------------------------
-- Generic Data Characteristic - metrics
-------------------------------------------------------------------------------
local p_nexxt_gdm = Proto("nexxt_gdm", "Nexxtender Generic Data: Metrics")

local f_gdm_unknown = ProtoField.bytes("gdm.unknown", "Unknown")

p_nexxt_gdm.fields = {
    f_gdm_unknown
}

function p_nexxt_gdm.dissector(buf, pinfo, tree)
    print("p_nexxt_gdm.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 20 then
        return
    end
    pinfo.cols.protocol = p_nexxt_gmdm.name
    local subtree = tree:add(p_nexxt_gdm, buf())
    subtree:add_le(f_gdm_unknown, buf())
end

-------------------------------------------------------------------------------
-- Generic Data Characteristic - badge
-------------------------------------------------------------------------------
local p_nexxt_gdb = Proto("nexxt_gdb", "Nexxtender Generic Data: Badge")

local f_gdb_uidLength = ProtoField.uint8("gdb.UIDLength", "UIDLength", base.DEC)
local f_gdb_uid = ProtoField.bytes("gsd.uid", "UUID")

p_nexxt_gdb.fields = {
    f_gdb_uidLength,
    f_gdb_uid
}

function p_nexxt_gdb.dissector(buf, pinfo, tree)
    print("p_nexxt_gdb.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if (length ~= 4) and (length ~= 7) and (length ~= 10) then
        return
    end
    pinfo.cols.protocol = p_nexxt_gdb.name
    local subtree = tree:add(p_nexxt_gdb, buf())
    subtree:add_le(f_gdb_uidLength, buf(0, 1))
    subtree:add_le(f_gde_data, buf(1))
end

-------------------------------------------------------------------------------
-- Generic Data Characteristic - time
-------------------------------------------------------------------------------
local p_nexxt_gdt = Proto("nexxt_gdt", "Nexxtender Generic Data: Time")

local f_gdt_timeStamp = ProtoField.absolute_time("gdt.TimeStamp", "TimeStamp", base.LOCAL)

p_nexxt_gdt.fields = {
    f_gdt_timeStamp
}

function p_nexxt_gdt.dissector(buf, pinfo, tree)
    print("p_nexxt_gdt.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if (length ~= 4) then
        return
    end
    pinfo.cols.protocol = p_nexxt_gdt.name
    local subtree = tree:add(p_nexxt_gdt, buf())
    subtree:add_le(f_gdt_timeStamp, buf(0, 4))
end

-------------------------------------------------------------------------------
-- Generic Data Characteristic - config 1_0
-------------------------------------------------------------------------------
local p_nexxt_gdc1_0 = Proto("nexxt_gdc1_0", "Nexxtender Generic Data: Config 1.0")

local f_gdc1_0_maxGrid = ProtoField.uint8("gdc1_0.maxGrid", "MaxGrid", base.DEC)
local modeValues = {
    [0x00] = "Eco Private",
    [0x01] = "Max Private",
    [0x04] = "Eco Open",
    [0x05] = "Max Open"
}
local f_gdc1_0_mode = ProtoField.uint8("gdc1_0.mode", "Mode", base.HEX, modeValues)
local f_gdc1_0_safe = ProtoField.uint8("gdc1_0.safe", "Safe", base.DEC)
local f_gdc1_0_touWeekStart = ProtoField.uint16("gdc1_0.touWeekStart", "TouWeekStart", base.DEC)
local f_gdc1_0_touWeekEnd = ProtoField.uint16("gdc1_0.touWeekEnd", "TouWeekEnd", base.DEC)
local f_gdc1_0_touWeekendStart = ProtoField.uint16("gdc1_0.touWeekendStart", "TouWeekendStart", base.DEC)
local f_gdc1_0_touWeekendEnd = ProtoField.uint16("gdc1_0.touWeekendEnd", "TouWeekendEnd", base.DEC)
local f_gdc1_0_crc16 = ProtoField.uint16("gdc1_0.crc16", "crc16", base.HEX)
local f_gdc1_0_crcIncorrect =
    ProtoExpert.new("cad.gdc1_0.wrong", "CRC incorrect", expert.group.CHECKSUM, expert.severity.ERROR)

p_nexxt_gdc1_0.fields = {
    f_gdc1_0_maxGrid,
    f_gdc1_0_mode,
    f_gdc1_0_safe,
    f_gdc1_0_touWeekStart,
    f_gdc1_0_touWeekEnd,
    f_gdc1_0_touWeekendStart,
    f_gdc1_0_touWeekendEnd,
    f_gdc1_0_crc16
}

p_nexxt_gdc1_0.experts = {
    f_gdc1_0_crcIncorrect
}

function p_nexxt_gdc1_0.dissector(buf, pinfo, tree)
    print("p_nexxt_gdc1_0.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if (length ~= 13) then
        return
    end
    pinfo.cols.protocol = p_nexxt_gdc1_0.name
    local subtree = tree:add(p_nexxt_gdc1_0, buf())
    subtree:add_packet_field(f_gdc1_0_maxGrid, buf(0, 1), ENC_LITTLE_ENDIAN, "A")
    subtree:add_le(f_gdc1_0_mode, buf(1, 1))
    subtree:add_packet_field(f_gdc1_0_safe, buf(2, 1), ENC_LITTLE_ENDIAN, "A")
    subtree:add_le(f_gdc1_0_touWeekStart, buf(3, 2)):append_text(touString(buf(3, 2):le_uint()))
    subtree:add_le(f_gdc1_0_touWeekEnd, buf(5, 2)):append_text(touString(buf(5, 2):le_uint()))
    subtree:add_le(f_gdc1_0_touWeekendStart, buf(7, 2)):append_text(touString(buf(7, 2):le_uint()))
    subtree:add_le(f_gdc1_0_touWeekendEnd, buf(9, 2)):append_text(touString(buf(9, 2):le_uint()))
    local treeitem = subtree:add_le(f_gdc1_0_crc16, buf(11, 2))
    local computedCrc = crc16_modbus(buf:bytes(), 0, 11)
    local receivedCrc = buf:bytes(11, 2):le_uint()
    print("Computed crc: " .. string.format("0x%04x", computedCrc))
    if (receivedCrc ~= computedCrc) then
        treeitem:add_proto_expert_info(f_gdc1_0_crcIncorrect, string.format("Expected CRC value 0x%04x", computedCrc))
    end
end

-------------------------------------------------------------------------------
-- Generic Data Characteristic - config 1_1
-------------------------------------------------------------------------------
local p_nexxt_gdc1_1 = Proto("nexxt_gdc1_1", "Nexxtender Generic Data: Config 1.1")

local f_gdc1_1_maxGrid = ProtoField.uint8("gdc1_1.maxGrid", "MaxGrid", base.DEC)
local f_gdc1_1_maxDevice = ProtoField.uint8("gdc1_1.maxDevice", "MaxDevice", base.DEC)
local f_gdc1_1_mode = ProtoField.uint8("gdc1_1.mode", "Mode", base.HEX, modeValues)
local f_gdc1_1_safe = ProtoField.uint8("gdc1_1.safe", "Safe", base.DEC)
local networkTypeValues = {
    [0x00] = "Mono/Tri+N",
    [0x02] = "Tri"
}
local f_gdc1_1_networkType = ProtoField.uint8("gdc1_1.networkType", "NetworkType", base.HEX, networkTypeValues)

local f_gdc1_1_touWeekStart = ProtoField.uint16("gdc1_1.touWeekStart", "TouWeekStart", base.DEC)
local f_gdc1_1_touWeekEnd = ProtoField.uint16("gdc1_1.touWeekEnd", "TouWeekEnd", base.DEC)
local f_gdc1_1_touWeekendStart = ProtoField.uint16("gdc1_1.touWeekendStart", "TouWeekendStart", base.DEC)
local f_gdc1_1_touWeekendEnd = ProtoField.uint16("gdc1_1.touWeekendEnd", "TouWeekendEnd", base.DEC)
local f_gdc1_1_crc16 = ProtoField.uint16("gdc1_1.crc16", "crc16", base.HEX)
local f_gdc1_1_crcIncorrect =
    ProtoExpert.new("cad.gdc1_1.wrong", "CRC incorrect", expert.group.CHECKSUM, expert.severity.ERROR)

p_nexxt_gdc1_1.fields = {
    f_gdc1_1_maxGrid,
    f_gdc1_1_maxDevice,
    f_gdc1_1_mode,
    f_gdc1_1_safe,
    f_gdc1_1_networkType,
    f_gdc1_1_touWeekStart,
    f_gdc1_1_touWeekEnd,
    f_gdc1_1_touWeekendStart,
    f_gdc1_1_touWeekendEnd,
    f_gdc1_1_crc16
}

p_nexxt_gdc1_1.experts = {
    f_gdc1_1_crcIncorrect
}
function touString(timeInMinutes)
    time = os.time({year = 1970, month = 1, day = 1, hour = 24, min = timeInMinutes})
    times = " (" .. os.date("%H:%M", time) .. ")"
    return times
end

function p_nexxt_gdc1_1.dissector(buf, pinfo, tree)
    print("p_nexxt_gdc1_1.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if (length ~= 15) then
        return
    end
    pinfo.cols.protocol = p_nexxt_gdc1_1.name
    local subtree = tree:add(p_nexxt_gdc1_1, buf())
    subtree:add_packet_field(f_gdc1_1_maxGrid, buf(0, 1), ENC_LITTLE_ENDIAN, "A")
    subtree:add_packet_field(f_gdc1_1_maxDevice, buf(1, 1), ENC_LITTLE_ENDIAN, "A")
    subtree:add_le(f_gdc1_1_mode, buf(2, 1))
    subtree:add_packet_field(f_gdc1_1_safe, buf(3, 1), ENC_LITTLE_ENDIAN, "A")
    subtree:add_le(f_gdc1_1_networkType, buf(4, 1))
    subtree:add_le(f_gdc1_1_touWeekStart, buf(5, 2)):append_text(touString(buf(5, 2):le_uint()))
    subtree:add_le(f_gdc1_1_touWeekEnd, buf(7, 2)):append_text(touString(buf(7, 2):le_uint()))
    subtree:add_le(f_gdc1_1_touWeekendStart, buf(9, 2)):append_text(touString(buf(9, 2):le_uint()))
    subtree:add_le(f_gdc1_1_touWeekendEnd, buf(11, 2)):append_text(touString(buf(11, 2):le_uint()))
    local treeitem = subtree:add_le(f_gdc1_1_crc16, buf(13, 2))
    local computedCrc = crc16_modbus(buf:bytes(), 0, 13)
    local receivedCrc = buf:bytes(13, 2):le_uint()
    print("Computed crc: " .. string.format("0x%04x", computedCrc))
    if (receivedCrc ~= computedCrc) then
        treeitem:add_proto_expert_info(f_gdc1_1_crcIncorrect, string.format("Expected CRC value 0x%04x", computedCrc))
    end
end
-------------------------------------------------------------------------------
-- Generic Data Characteristic - config CBOR
-------------------------------------------------------------------------------
local p_nexxt_gdcCBOR = Proto("nexxt_gdcCBOR", "Nexxtender Generic Data: Config CBOR")

local f_gdcCBOR_crc16 = ProtoField.uint16("gdcCBOR.crc16", "crc16", base.HEX)
local f_gdcCBOR_crcIncorrect =
    ProtoExpert.new("cad.gdcCBOR.wrong", "CRC incorrect", expert.group.CHECKSUM, expert.severity.ERROR)

p_nexxt_gdcCBOR.fields = {
    f_gdcCBOR_crc16
}

p_nexxt_gdcCBOR.experts = {
    f_gdcCBOR_crcIncorrect
}
function p_nexxt_gdcCBOR.dissector(buf, pinfo, tree)
    print("p_nexxt_gdcCBOR.dissector: ", buf:bytes():tohex())
    pinfo.cols.protocol = p_nexxt_gdcCBOR.name
    local subtree = tree:add(p_nexxt_gdcCBOR, buf())
    cborDissector = Dissector.get("cbor")
    -- TODO: complete and test. Requires a trace of the command.
    cborDissector.dissector(buf, pinfo, tree)
    local dataLength = buf:len() - 2
    local treeitem = subtree:add_le(f_gdcCBOR_crc16, buf(dataLength, 2))
    local computedCrc = crc16_modbus(buf:bytes(), 0, dataLength)
    local receivedCrc = buf:bytes(dataLength, 2):le_uint()
    print("Computed crc: " .. string.format("0x%04x", computedCrc))
    if (receivedCrc ~= computedCrc) then
        treeitem:add_proto_expert_info(f_gdcCBOR_crcIncorrect, string.format("Expected CRC value 0x%04x", computedCrc))
    end
end

-------------------------------------------------------------------------------
-- Generic Data Characteristic - config
-------------------------------------------------------------------------------
local p_nexxt_gdc = Proto("nexxt_gdc", "Nexxtender Generic Data: Config")

local f_gdt_timeStamp = ProtoField.absolute_time("gdt.TimeStamp", "TimeStamp", base.LOCAL)

function p_nexxt_gdc.dissector(buf, pinfo, tree)
    print("p_nexxt_gdc.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if (length == 13) then
        p_nexxt_gdc1_0.dissector(buf, pinfo, tree)
    elseif (length == 15) then
        p_nexxt_gdc1_1.dissector(buf, pinfo, tree)
    else
        p_nexxt_gdcCBOR.dissector(buf, pinfo, tree)
    end
end

-------------------------------------------------------------------------------
-- Generic DATA Characteristic
-------------------------------------------------------------------------------
local p_nexxt_gd = Proto("nexxt_gd", "Nexxtender Generic Data")

local gdDissectors = {
    [0x00] = p_nexxt_gdl.dissector,
    [0x10] = p_nexxt_gde.dissector,
    [0x20] = p_nexxt_gdm.dissector,
    [0x30] = p_nexxt_gdb.dissector,
    [0x40] = p_nexxt_gdt.dissector,
    [0x50] = p_nexxt_gdc.dissector
}

print("fuut.lua defining Generic/CDR Generic Data")

function p_nexxt_gd.dissector(buf, pinfo, tree)
    print("p_nexxt_gd.dissector: ", buf:bytes():tohex())
    length = buf:len()
    pinfo.cols.protocol = p_nexxt_gd.name
    local lastOperationType = GetLastOperationType(pinfo.number)
    print("p_nexxt_gd.dissector using lastOperationType:", lastOperationType)
    local dissector = gdDissectors[lastOperationType]

    if dissector ~= nil then
        dissector:call(buf, pinfo, tree)
    end
end

print("fuut.lua defined Generic/CDR Generic Command")

-------------------------------------------------------------------------------
-- CDR Command Characteristic
-------------------------------------------------------------------------------
local p_nexxt_cdrc = Proto("nexxt_cdrc", "Nexxtender CDR Command")

local cdrOperationValues = {
    [0x01] = "Next?",
}
local f_cdrc_operationId = ProtoField.uint8("cdrc.operationId", "OperationId", base.HEX, cdrOperationValues)

p_nexxt_cdrc.fields = {
    f_cdrc_operationId,
}


function p_nexxt_cdrc.dissector(buf, pinfo, tree)
    print("p_nexxt_cdrc.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 1 then
        return
    end
    pinfo.cols.protocol = p_nexxt_cdrc.name
    local subtree = tree:add(p_nexxt_cdrc, buf())
    subtree:add_le(f_cdrc_operationId, buf(0, 1))
end

-------------------------------------------------------------------------------
-- CDR STATUS Characteristic
-------------------------------------------------------------------------------
local p_nexxt_cdrs = Proto("nexxt_cdrs", "Nexxtender CDR Status")

local f_cdrs_remainingRecords = ProtoField.uint8("cdrs.remainingRecords", "RemainingRecords", base.DEC)

p_nexxt_cdrs.fields = {
    f_cdrs_remainingRecords,
}

function p_nexxt_cdrs.dissector(buf, pinfo, tree)
    print("p_nexxt_cdrs.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 4 then
        return
    end
    pinfo.cols.protocol = p_nexxt_cdrs.name
    local subtree = tree:add(p_nexxt_cdrs, buf())
    subtree:add_le(f_cdrs_remainingRecords, buf(0, 4))
end

-------------------------------------------------------------------------------
-- CDR Record Characteristic 
-------------------------------------------------------------------------------
local p_nexxt_cdrr = Proto("nexxt_cdrr", "Nexxtender CDR Record")

local f_cdrr_unknown1 = ProtoField.uint32("cdrr.unknown1", "Unknown1", base.HEX)
local f_cdrr_sessionStartTime = ProtoField.absolute_time("cdrr.sessionStartTime", "SessionStartTime", base.LOCAL)
local f_cdrr_sessionStartEnergy = ProtoField.uint32("cdrr.sessionStartEnergy", "SessionStartEnergy", base.DEC)
local f_cdrr_unknown2 = ProtoField.uint32("cdrr.unknown2", "Unknown2", base.HEX)
local f_cdrr_unknown3 = ProtoField.uint32("cdrr.unknown3", "Unknown3", base.HEX)
local f_cdrr_sessionStopTime = ProtoField.absolute_time("cdrr.sessionStopTime", "SessionStopTime", base.LOCAL)
local f_cdrr_sessionStopEnergy = ProtoField.uint32("cdrr.sessionStopEnergy", "SessionStopEnergy", base.DEC)
local f_cdrr_unknown4 = ProtoField.uint16("cdrr.unknown4", "Unknown4", base.HEX)
local f_cdrr_crc16 = ProtoField.uint16("cdrr.crc16", "crc16", base.HEX)

local f_cdrr_crcIncorrect =
    ProtoExpert.new("cdrr.crc16.wrong", "CRC incorrect", expert.group.CHECKSUM, expert.severity.ERROR)

p_nexxt_cdrr.fields = {
    f_cdrr_unknown1,
    f_cdrr_sessionStartTime,
    f_cdrr_sessionStartEnergy,
    f_cdrr_unknown2,
    f_cdrr_unknown3,
    f_cdrr_sessionStopTime,
	f_cdrr_sessionStopEnergy,
	f_cdrr_unknown4,
	f_cdrr_crc16
}

p_nexxt_cdrr.experts = {
    f_cdrr_crcIncorrect
}

function p_nexxt_cdrr.dissector(buf, pinfo, tree)
    print("p_nexxt_gde.dissector: ", buf:bytes():tohex())
    length = buf:len()
    if length ~= 32 then
        return
    end
    pinfo.cols.protocol = p_nexxt_cdrr.name
    local subtree = tree:add(p_nexxt_cdrr, buf())
    subtree:add_le(f_cdrr_unknown1, buf(0, 4))
    subtree:add_le(f_cdrr_sessionStartTime, buf(4, 4))
    subtree:add_packet_field(f_cdrr_sessionStartEnergy, buf(8, 4), ENC_LITTLE_ENDIAN, "Wh")
    subtree:add_le(f_cdrr_unknown2, buf(12, 4))
    subtree:add_le(f_cdrr_unknown3, buf(16, 4))
    subtree:add_le(f_cdrr_sessionStopTime, buf(20, 4))
    subtree:add_packet_field(f_cdrr_sessionStopEnergy, buf(24, 4), ENC_LITTLE_ENDIAN, "Wh")
    subtree:add_le(f_cdrr_unknown4, buf(28, 2))
    local treeitem = subtree:add_le(f_cdrr_crc16, buf(30, 2))
    local computedCrc = crc16_modbus(buf:bytes(), 0, 30)
    local receivedCrc = buf:bytes(30, 2):le_uint()
    print("Computed crc: " .. string.format("0x%04x", computedCrc))
    if (receivedCrc ~= computedCrc) then
        treeitem:add_proto_expert_info(f_cdrr_crcIncorrect, string.format("Expected CRC value 0x%04x", computedCrc))
    end
end

print("fuut.lua defined CDR Command")
-------------------------------------------------------------------------------
-- Registering all dissectors
-------------------------------------------------------------------------------
print("fuut.lua registering dissectors")

local UUID_NEXXTENDER_BASE = "fd47416a-95fb-4206-88b5-b4a8045f75"
local UUID_NEXXTENDER_CHARGING_SERVICE = UUID_NEXXTENDER_BASE .. "c1"
local UUID_NEXXTENDER_CHARGING_BASIC_DATA_CHARACTERISTIC = UUID_NEXXTENDER_BASE .. "cf"
local UUID_NEXXTENDER_CHARGING_GRID_DATA_CHARACTERISTIC = UUID_NEXXTENDER_BASE .. "d0"
local UUID_NEXXTENDER_CHARGING_CAR_DATA_CHARACTERISTIC = UUID_NEXXTENDER_BASE .. "da"
local UUID_NEXXTENDER_CHARGING_ADVANCED_DATA_CHARACTERISTIC = UUID_NEXXTENDER_BASE .. "db"
local UUID_NEXXTENDER_GENERIC_COMMAND_CHARACTERISTIC = UUID_NEXXTENDER_BASE .. "dd"
local UUID_NEXXTENDER_GENERIC_STATUS_CHARACTERISTIC = UUID_NEXXTENDER_BASE .. "de"
local UUID_NEXXTENDER_GENERIC_DATA_CHARACTERISTIC = UUID_NEXXTENDER_BASE .. "df"
local UUID_NEXXTENDER_CDR_COMMAND_CHARACTERISTIC = UUID_NEXXTENDER_BASE .. "c2"
local UUID_NEXXTENDER_CDR_STATUS_CHARACTERISTIC = UUID_NEXXTENDER_BASE .. "c3"
local UUID_NEXXTENDER_CDR_RECORD_CHARACTERISTIC = UUID_NEXXTENDER_BASE .. "c4"

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
print("fuut.lua registering dissector p_nexxt_gd ")
bt_dissector:add(UUID_NEXXTENDER_GENERIC_DATA_CHARACTERISTIC, p_nexxt_gd)
print("fuut.lua registering dissector p_nexxt_cdrc ")
bt_dissector:add(UUID_NEXXTENDER_CDR_COMMAND_CHARACTERISTIC, p_nexxt_cdrc)
print("fuut.lua registering dissector p_nexxt_cdrs ")
bt_dissector:add(UUID_NEXXTENDER_CDR_STATUS_CHARACTERISTIC, p_nexxt_cdrs)
print("fuut.lua registering dissector p_nexxt_cdrr ")
bt_dissector:add(UUID_NEXXTENDER_CDR_RECORD_CHARACTERISTIC, p_nexxt_cdrr)

print("fuut.lua end")
