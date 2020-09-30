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
    prt      = ProtoField.new("Priority", "egts.prt", ftypes.UINT8, nil, base.DEC, 0x3),
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
    srt      = ProtoField.new("Subrecord type", "egts.srt", ftypes.UINT8, nil, base.DEC),
    srl      = ProtoField.new("Subrecord length", "egts.srl", ftypes.UINT16, nil, base.DEC),
    srd      = ProtoField.new("Subrecord data", "egts.srd", ftypes.BYTES),
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

local function parse_sdr(buf, tree)
    local current_offset = 0
    local sdr_len = buf:range(current_offset, 2):le_uint()
    local service_data_record = tree:add(egts_proto, buf, "Service Data Record")
    current_offset = current_offset + 2

    service_data_record:add(header.rl, sdr_len)
    service_data_record:add(header.rn, buf:range(current_offset, 2):le_uint())
    current_offset = current_offset + 2

    local rfl = buf:range(current_offset, 1):uint()
    service_data_record:add(header.ssod, rfl)
    service_data_record:add(header.rsod, rfl)
    service_data_record:add(header.grp, rfl)
    service_data_record:add(header.rpr, rfl)
    service_data_record:add(header.tmfe, rfl)
    service_data_record:add(header.evfe, rfl)
    service_data_record:add(header.obfe, rfl)
    current_offset = current_offset + 1

    if bit.band(rfl, 0x1) ~= 0 then
        -- если флаг OBFE установлен, то значит есть поле с id объекта и его надо заполнить
        service_data_record:add(header.oid, buf:range(current_offset, 4):le_uint())
        current_offset = current_offset + 4
    end

    if bit.band(rfl, 0x2) ~= 0 then
        -- если флаг EVFE установлен, то значит присутствует поле с id события
        service_data_record:add(header.evid, buf:range(current_offset, 4):le_uint())
        current_offset = current_offset + 4
    end

    if bit.band(rfl, 0x4) ~= 0 then
        -- если флаг TMFE установлен, то есть поле со временем, которое нужно разобрать
        service_data_record:add(header.tm, buf:range(current_offset, 4):le_uint())
        current_offset = current_offset + 4
    end

    service_data_record:add(header.sst, buf:range(current_offset, 1):uint())
    current_offset = current_offset + 1

    service_data_record:add(header.rst, buf:range(current_offset, 1):uint())
    current_offset = current_offset + 1

    service_data_record:add(header.rd, buf:range(current_offset, sdr_len):raw())
    current_offset = current_offset + sdr_len

    return current_offset
end

local function parse_pt_response (buf, tree)
    local current_offset = 0
    tree:add(header.rpid, buf:range(current_offset, 2):le_uint())
    current_offset = current_offset + 2

    tree:add(header.pr, buf:range(current_offset, 1):uint())
    current_offset = current_offset + 1

    local computed_bytes = current_offset
    while (current_offset < buf:len()) do
        computed_bytes = parse_sdr(buf:range(current_offset), tree)
        current_offset = current_offset + computed_bytes
    end

    return buf:len()
end

local function parse_pt_appdata (buf, tree)
    local current_offset = 0
    local computed_bytes = 0
    while (current_offset < buf:len()) do
        computed_bytes = parse_sdr(buf:range(current_offset), tree)
        current_offset = current_offset + computed_bytes
    end

    return current_offset
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
    tree:add(header.pid, tvbuf:range(7, 2):uint())

    local packet_type_id = tvbuf:range(9, 1):uint()
    tree:add(header.pt, packet_type_id)

    local field_offset = 10;

    if bit.band(prf_tvbr, 0x20) ~= 0 then
        -- если RTE флаг присутствует, то заполняем не обязательные поля

        tree:add(header.pra, tvbuf:range(field_offset, 2):le_uint())
        field_offset = field_offset + 2
        tree:add(header.rca, tvbuf:range(field_offset, 2):le_uint())
        field_offset = field_offset + 2
        tree:add(header.ttl, tvbuf:range(field_offset, 1):uint())
        field_offset = field_offset + 1
    end
    tree:add(header.hcs, tvbuf:range(field_offset, 1):uint())
    field_offset = field_offset + 1

    local subtree = tree:add(egts_proto, tvbuf, "Services frame data")
    if get_packet_type(packet_type_id) == EGTS_PT_RESPONSE then
        parse_pt_response(tvbuf:range(field_offset, data_len), subtree)
    elseif get_packet_type(packet_type_id) == EGTS_PT_APPDATA then
        parse_pt_appdata(tvbuf:range(field_offset, data_len), subtree)
    else
        parse_pt_signed_appdata(tvbuf:range(field_offset, data_len), subtree)
    end

    tree:add(header.sfrcs, tvbuf:range(field_offset + data_len, 2):le_uint())

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

