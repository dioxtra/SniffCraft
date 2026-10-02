-- SniffCraft dissector for Wireshark
--
-- Displays the Minecraft packets captured by the SniffCraft proxy, either live
-- (SniffCraft extcap interface) or from the .pcapng files SniffCraft writes
-- when "LogToPcapng" is enabled in its conf file.
--
-- Install: copy this file to the personal Lua plugins folder
-- (Help > About Wireshark > Folders), e.g. %APPDATA%\Wireshark\plugins
--
-- Each packet is stored as an exported PDU (LINKTYPE_WIRESHARK_UPPER_PDU) with
-- the "sniffcraft" dissector name, followed by this record (big endian):
--
--   magic          4 bytes   "SCMC"
--   format         u8        1
--   origin         u8        sniffcraft Endpoint enum
--   state          u8        ProtocolCraft ConnectionState, 255 for None
--   flags          u8        bit 0: parse error, bit 1: fields have byte offsets
--   protocol       u32       Minecraft protocol version
--   connection     u32       SniffCraft connection index
--   wire size      u32       bytes on the wire (compressed/encrypted), 0 if injected by SniffCraft
--   packet id      i32
--   name           u16 length + utf8
--   raw            u32 length + uncompressed packet bytes (packet id included)
--   fields         u32 count + count * {
--                      kind u8 (0 value, 1 object, 2 array, 3 truncated), depth u16,
--                      name u16 length + utf8, value u32 length + utf8,
--                      start u32, end u32 (byte range in raw, 0xFFFFFFFF if unknown) }
--   json           u32 length + utf8 (optional ProtocolCraft json, length 0 if absent)

local sniffcraft = Proto("sniffcraft", "SniffCraft Minecraft")

local origins = {
    [0] = "Server",
    [1] = "Client",
    [2] = "SniffCraft to server",
    [3] = "SniffCraft to client",
    [4] = "Server to SniffCraft",
    [5] = "Client to SniffCraft",
}

-- { source, destination, logical sender (for packet direction) }
local origin_endpoints = {
    [0] = { "Server", "Client", "server" },
    [1] = { "Client", "Server", "client" },
    [2] = { "SniffCraft", "Server", "client" },
    [3] = { "SniffCraft", "Client", "server" },
    [4] = { "Server", "SniffCraft", "server" },
    [5] = { "Client", "SniffCraft", "client" },
}

local states = {
    [0] = "Handshake",
    [1] = "Status",
    [2] = "Login",
    [3] = "Play",
    [4] = "Configuration",
    [255] = "None",
}

local kinds = { VALUE = 0, OBJECT = 1, ARRAY = 2, TRUNCATED = 3 }
local unknown_offset = 0xFFFFFFFF

local f = sniffcraft.fields
f.origin = ProtoField.uint8("sniffcraft.origin", "Origin", base.DEC, origins)
f.direction = ProtoField.string("sniffcraft.direction", "Direction")
f.state = ProtoField.uint8("sniffcraft.state", "State", base.DEC, states)
f.flags = ProtoField.uint8("sniffcraft.flags", "Flags", base.HEX)
f.parse_error = ProtoField.bool("sniffcraft.flags.parse_error", "Parse error", 8, nil, 0x01)
f.has_offsets = ProtoField.bool("sniffcraft.flags.has_offsets", "Fields have byte offsets", 8, nil, 0x02)
f.protocol_version = ProtoField.uint32("sniffcraft.protocol_version", "Protocol version", base.DEC)
f.connection = ProtoField.uint32("sniffcraft.connection", "Connection", base.DEC)
f.wire_size = ProtoField.uint32("sniffcraft.wire_size", "Size on the wire", base.DEC)
f.id = ProtoField.int32("sniffcraft.id", "Packet id", base.DEC)
f.name = ProtoField.string("sniffcraft.name", "Packet name")
f.raw = ProtoField.bytes("sniffcraft.raw", "Packet bytes")
f.field = ProtoField.string("sniffcraft.field", "Field")
f.field_path = ProtoField.string("sniffcraft.field.path", "Field path")
f.json = ProtoField.string("sniffcraft.json", "JSON")

local ef_parse_error = ProtoExpert.new("sniffcraft.parse_error.expert", "SniffCraft couldn't parse this packet",
    expert.group.MALFORMED, expert.severity.WARN)
local ef_bad_record = ProtoExpert.new("sniffcraft.bad_record", "Invalid SniffCraft record",
    expert.group.MALFORMED, expert.severity.ERROR)
sniffcraft.experts = { ef_parse_error, ef_bad_record }

local json_dissector = Dissector.get("json")

local function read_string(tvb, offset, length)
    if length == 0 then
        return ""
    end
    return tvb(offset, length):string(ENC_UTF_8)
end

-- Byte range of a field inside the raw packet bytes, nil if unknown
local function field_range(raw_tvb, start, stop)
    if raw_tvb == nil or start == unknown_offset or stop <= start or stop > raw_tvb:len() then
        return nil
    end
    return raw_tvb(start, stop - start)
end

local function add_fields(tvb, offset, count, tree, raw_tvb)
    local parents = { [0] = tree }
    local path = {}
    for _ = 1, count do
        local kind = tvb(offset, 1):uint()
        local depth = tvb(offset + 1, 2):uint()
        local name_len = tvb(offset + 3, 2):uint()
        local name = read_string(tvb, offset + 5, name_len)
        offset = offset + 5 + name_len
        local value_len = tvb(offset, 4):uint()
        local value = read_string(tvb, offset + 4, value_len)
        offset = offset + 4 + value_len
        local start = tvb(offset, 4):uint()
        local stop = tvb(offset + 4, 4):uint()
        offset = offset + 8

        path[depth] = name
        for d = #path, depth + 1, -1 do
            path[d] = nil
        end
        local full_path = path[0] or ""
        for d = 1, depth do
            local part = path[d] or ""
            full_path = full_path .. (part:sub(1, 1) == "[" and "" or ".") .. part
        end

        local label
        if kind == kinds.VALUE then
            label = name .. ": " .. value
        elseif kind == kinds.ARRAY then
            label = name .. " (" .. value .. ")"
        elseif kind == kinds.TRUNCATED then
            label = "... " .. value
        else
            label = name
        end

        local parent = parents[depth] or tree
        local range = field_range(raw_tvb, start, stop)
        local item
        if range ~= nil then
            item = parent:add(f.field, range, label)
        else
            item = parent:add(f.field, label)
        end
        item:set_text(label)
        item:add(f.field_path, full_path):set_hidden()

        if kind == kinds.OBJECT or kind == kinds.ARRAY then
            parents[depth + 1] = item
        end
    end
    return offset
end

function sniffcraft.dissector(tvb, pinfo, tree)
    if tvb:len() < 24 or tvb(0, 4):string() ~= "SCMC" then
        return 0
    end

    local origin = tvb(5, 1):uint()
    local state = tvb(6, 1):uint()
    local flags = tvb(7, 1):uint()
    local protocol_version = tvb(8, 4):uint()
    local packet_id = tvb(20, 4):int()
    local endpoints = origin_endpoints[origin] or { "?", "?", "client" }
    local clientbound = endpoints[3] == "server"

    local subtree = tree:add(sniffcraft, tvb())
    subtree:add(f.origin, tvb(5, 1))
    subtree:add(f.direction, clientbound and "clientbound" or "serverbound"):set_generated()
    subtree:add(f.state, tvb(6, 1))
    local flags_item = subtree:add(f.flags, tvb(7, 1))
    flags_item:add(f.parse_error, tvb(7, 1))
    flags_item:add(f.has_offsets, tvb(7, 1))
    subtree:add(f.protocol_version, tvb(8, 4))
    subtree:add(f.connection, tvb(12, 4))
    subtree:add(f.wire_size, tvb(16, 4))
    subtree:add(f.id, tvb(20, 4))

    local ok, err = pcall(function()
        local offset = 24
        local name_len = tvb(offset, 2):uint()
        local name = read_string(tvb, offset + 2, name_len)
        if name_len > 0 then
            subtree:add(f.name, tvb(offset + 2, name_len), name)
        end
        offset = offset + 2 + name_len

        local raw_len = tvb(offset, 4):uint()
        local raw_tvb = nil
        if raw_len > 0 then
            subtree:add(f.raw, tvb(offset + 4, raw_len))
            -- Separate data source so field byte ranges match the Minecraft packet
            raw_tvb = tvb(offset + 4, raw_len):tvb("Minecraft packet")
        end
        offset = offset + 4 + raw_len

        local field_count = tvb(offset, 4):uint()
        offset = offset + 4
        local packet_tree = tree:add(sniffcraft, tvb(), "Minecraft " .. (name ~= "" and name or "packet"))
        packet_tree:set_text((name ~= "" and name or string.format("Unknown packet 0x%02X", packet_id))
            .. " (" .. (states[state] or "?") .. ", " .. (clientbound and "clientbound" or "serverbound") .. ")")
        offset = add_fields(tvb, offset, field_count, packet_tree, raw_tvb)

        -- Native parsing of the raw bytes (minecraft.lua), when installed
        if raw_tvb ~= nil and _G.minecraft_native ~= nil then
            _G.minecraft_native.dissect_packet(raw_tvb, pinfo, tree, protocol_version, state, clientbound)
        end

        local json_len = tvb(offset, 4):uint()
        if json_len > 0 then
            subtree:add(f.json, tvb(offset + 4, json_len))
            if json_dissector ~= nil then
                json_dissector:call(tvb(offset + 4, json_len):tvb(), pinfo, subtree)
            end
        end

        if flags % 2 == 1 then
            subtree:add_proto_expert_info(ef_parse_error)
        end

        local state_name = states[state] or "?"
        pinfo.cols.protocol:set("Minecraft")
        pinfo.cols.src:set(endpoints[1])
        pinfo.cols.dst:set(endpoints[2])
        pinfo.cols.info:set(string.format("%s [%s] %s", clientbound and "S → C" or "C → S", state_name,
            name ~= "" and name or string.format("UNPARSED id=0x%02X", packet_id)))
    end)
    if not ok then
        subtree:add_proto_expert_info(ef_bad_record, tostring(err))
        pinfo.cols.protocol:set("Minecraft")
    end

    return tvb:len()
end
