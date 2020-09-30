-- создаем описание нового протокола
local egts_proto = Proto("egts", "EGTS")

-- настройки плагина
local default_settings =
{
    port = 20629
}

local EGTS_PT_RESPONSE = "EGTS_PT_RESPONSE"
local EGTS_PT_APPDATA = "EGTS_PT_APPDATA"
local EGTS_PT_SIGNED_APPDATA = "EGTS_PT_SIGNED_APPDATA"

local egts_packet_type = {
    [0] = EGTS_PT_RESPONSE,
    [1] = EGTS_PT_APPDATA,
    [2] = EGTS_PT_SIGNED_APPDATA,
}

local header =
{

    prv      = ProtoField.new("ProtocolVersion", "egts.prv", ftypes.UINT8, nil, base.DEC),
    skid     = ProtoField.new("SecurityKeyID", "egts.skid", ftypes.UINT8, nil, base.DEC),
    prf      = ProtoField.new("Prefix", "egts.prf", ftypes.UINT8, nil, base.DEC, 0xc0),
    rte      = ProtoField.new("Route", "egts.rte", ftypes.UINT8, nil, base.DEC, 0x20),
    ena      = ProtoField.new("Encryption alg", "egts.ena", ftypes.UINT8, nil, base.DEC, 0x18),
    cmp      = ProtoField.new("Compression", "egts.cmp", ftypes.UINT8, nil, base.DEC, 0x4),
    priority = ProtoField.new("Priority", "egts.pr", ftypes.UINT8, nil, base.DEC, 0x3),
    hl       = ProtoField.new("Header length", "egts.hl", ftypes.UINT8, nil, base.DEC),
    he       = ProtoField.new("Header encoding", "egts.he", ftypes.UINT8, nil, base.DEC),
    fdl      = ProtoField.new("Frame data length", "egts.fdl", ftypes.UINT16, nil, base.DEC),
    pid      = ProtoField.new("Packet identifier", "egts.pid", ftypes.UINT16, nil, base.DEC),
    pt       = ProtoField.new("Packet type", "egts.pt", ftypes.UINT8, egts_packet_type, base.DEC),
    pra      = ProtoField.new("Peer address", "egts.pra", ftypes.UINT16, nil, base.DEC),
    rca      = ProtoField.new("Recipient address", "egts.rca", ftypes.UINT16, nil, base.DEC),
    ttl      = ProtoField.new("Time to live", "egts.ttl", ftypes.UINT8, nil, base.DEC),
    hcs      = ProtoField.new("Header checksum", "egts.hcs", ftypes.UINT8, nil, base.HEX),
    sfrd     = ProtoField.new("Services frame data", "egts.sfrd", ftypes.BYTES),
    rpid     = ProtoField.new("Response packetID", "egts.rpid", ftypes.UINT16, nil, base.DEC),
    pr       = ProtoField.new("Processing result", "egts.pr", ftypes.UINT8, nil, base.DEC),
    rl       = ProtoField.new("Record length", "egts.rl", ftypes.UINT16, nil, base.DEC),
    rn       = ProtoField.new("Record number", "egts.rn", ftypes.UINT16, nil, base.DEC),
    ssod     = ProtoField.new("Source service on device", "egts.ssod", ftypes.UINT8, nil, base.DEC, 0x80),
    rsod     = ProtoField.new("Recipient service on device", "egts.rsod", ftypes.UINT8, nil, base.DEC, 0x40),
    grp      = ProtoField.new("Group", "egts.grp", ftypes.UINT8, nil, base.DEC, 0x20),
    rpr      = ProtoField.new("Record processing priority", "egts.rpr", ftypes.UINT8, nil, base.DEC, 0x18),
    tmfe     = ProtoField.new("Time field exists", "egts.tmfe", ftypes.UINT8, nil, base.DEC, 0x4),
    evfe     = ProtoField.new("Event ID field exists", "egts.evfe", ftypes.UINT8, nil, base.DEC, 0x2),
    obfe     = ProtoField.new("Object ID field exists", "egts.obfe", ftypes.UINT8, nil, base.DEC, 0x1),
    oid      = ProtoField.new("Object identifier", "egts.oid", ftypes.UINT32, nil, base.DEC),
    evid     = ProtoField.new("Event identifier", "egts.evid", ftypes.UINT32, nil, base.DEC),
    tm       = ProtoField.new("Time", "egts.tm", ftypes.UINT32, nil, base.DEC),
    sst      = ProtoField.new("Source service type", "egts.sst", ftypes.UINT8, nil, base.DEC),
    rst      = ProtoField.new("Recipient service type", "egts.rst", ftypes.UINT8, nil, base.DEC),
    rd       = ProtoField.new("Record data", "egts.rd", ftypes.BYTES),
    sfrcs    = ProtoField.new("Services frame data checksum", "egts.sfrcs", ftypes.UINT16, nil, base.HEX)
}

-- регистрация полей протокола
egts_proto.fields = header

local MIN_HEADE_LENGHT = 11

local function get_packet_type(type_id)
    return egts_packet_type[type_id]
end

local function get_egts_length(tvbuf, pktinfo, offset)
    local header_len = tvbuf:range(offset + 3, 1):uint()
    local data_len = tvbuf:range(offset + 5, 2):le_uint()

    return header_len + data_len + 2
end

local function parse_pt_response (buf, tree)
    tree:add(header.rpid, buf:range(0, 2):le_uint())
    tree:add(header.pr, buf:range(2, 1):uint())
    tree:add(header.sfrd, buf:range(3, -1):raw())

    return buf:len()
end

local function parse_pt_appdata (buf, tree)
    tree:add(header.sfrd, buf:raw())
    return buf:len()
end

local function parse_pt_signed_appdata (buf, tree)
    tree:add(header.sfrd, buf:raw())
    return buf:len()
end

local function dissect_egts_pdu(tvbuf, pktinfo, root)
    local header_len = tvbuf:range(3, 1):uint()
    local data_len = tvbuf:range(5, 2):le_uint()
    local msglen = header_len + data_len + 2

    pktinfo.cols.protocol:set("EGTS")

    -- Начинаем заполнения дерева в отображении
    local tree = root:add(egts_proto, tvbuf:range(0, msglen))

    tree:add(header.prv, tvbuf:range(0, 1):uint())
    tree:add(header.skid, tvbuf:range(1, 1):uint())

    local prf_tvbr = tvbuf:range(2, 1):uint()
    tree:add(header.prf, prf_tvbr)
    tree:add(header.rte, prf_tvbr)
    tree:add(header.ena, prf_tvbr)
    tree:add(header.cmp, prf_tvbr)
    tree:add(header.priority, prf_tvbr)

    tree:add(header.hl, header_len)
    tree:add(header.he, tvbuf:range(4, 1):uint())

    tree:add(header.fdl, data_len)
    tree:add(header.he, tvbuf:range(7, 1):uint())

    local packet_type_id = tvbuf:range(8, 1):uint()
    tree:add(header.pt, packet_type_id)
    tree:add(header.hcs, tvbuf:range(9, 1):uint())

    local field_offset = 10;

    if bit.band(prf_tvbr, 0x20) == 1 then
        -- если RTE флаг присутствует, то заполняем не обязательные поля

        tree:add(header.pra, tvbuf:range(field_offset, 2):le_uint())
        field_offset = field_offset + 2
        tree:add(header.rca, tvbuf:range(field_offset, 2):le_uint())
        field_offset = field_offset + 2
        tree:add(header.ttl, tvbuf:range(field_offset, 1):uint())
        field_offset = field_offset + 1
    end

    local subtree = tree:add(egts_proto, tvbuf, "Services frame data")
    if get_packet_type(packet_type_id) == EGTS_PT_RESPONSE then
        parse_pt_response(tvbuf:range(field_offset, data_len), subtree)
    elseif get_packet_type(packet_type_id) == EGTS_PT_APPDATA then
        parse_pt_appdata(tvbuf:range(field_offset, data_len), subtree)
    else
        parse_pt_signed_appdata(tvbuf:range(field_offset, data_len), subtree)
    end

    tree:add(header.sfrcs, tvbuf:range(field_offset, 2):le_uint())

    return msglen
end

-- задаем функию обработки, которая получает на вход данные tvbuf (объект Tvb), информацию о пакете
-- pktinfo (объект Pinfo) и root дерево распарсенного объекта.
function egts_proto.dissector(tvbuf, pktinfo, root)
    dissect_tcp_pdus(tvbuf, root, MIN_HEADE_LENGHT, get_egts_length, dissect_egts_pdu)
    local bytes_consumed = tvbuf:len()
    return bytes_consumed

end

-- добавляем парсер в таблицу
DissectorTable.get("tcp.port"):add(default_settings.port, egts_proto)

