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

local egts_subrecord_type = {
    [0]  = "EGTS_SR_RECORD_RESPONSE",
    [16] = "EGTS_SR_POS_DATA",
    [17] = "EGTS_SR_EXT_POS_DATA",
    [19] = "EGTS_SR_COUNTERS_DATA",
    [20] = "EGTS_SR_STATE_DATA",
    [22] = "EGTS_SR_LOOPIN_DATA",
    [23] = "EGTS_SR_ABS_DIG_SENS_DATA",
    [24] = "EGTS_SR_ABS_AN_SENS_DATA",
    [25] = "EGTS_SR_ABS_CNTR_DATA",
    [26] = "EGTS_SR_ABS_LOOPIN_DATA",
    [18] = "EGTS_SR_AD_SENSORS_DATA",
    [27] = "EGTS_SR_LIQUID_LEVEL_SENSOR",
    [28] = "EGTS_SR_PASSENGERS_COUNTERS",
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
    srt      = ProtoField.new("Subrecord type", "egts.srt", ftypes.UINT8, egts_subrecord_type, base.DEC),
    srl      = ProtoField.new("Subrecord length", "egts.srl", ftypes.UINT16, nil, base.DEC),
    srd      = ProtoField.new("Subrecord data", "egts.srd", ftypes.BYTES),
    crn      = ProtoField.new("Confirmed record number", "egts.crn", ftypes.UINT16, nil, base.DEC),
    rs       = ProtoField.new("Record status", "egts.rs", ftypes.UINT8, nil, base.DEC),
    ntm      = ProtoField.new("Navigation time", "egts.ntm", ftypes.ABSOLUTE_TIME),
    lat      = ProtoField.new("Latitude", "egts.lat", ftypes.DOUBLE),
    long     = ProtoField.new("Longitude", "egts.long", ftypes.DOUBLE),
    alte     = ProtoField.new("ALTE", "egts.alte", ftypes.UINT8, nil, base.DEC, 0x80),
    lohs     = ProtoField.new("LONS", "egts.lohs", ftypes.UINT8, nil, base.DEC, 0x40),
    lahs     = ProtoField.new("LAHS", "egts.lahs", ftypes.UINT8, nil, base.DEC, 0x20),
    mv       = ProtoField.new("MV", "egts.mv", ftypes.UINT8, nil, base.DEC, 0x10),
    bb       = ProtoField.new("BB", "egts.bb", ftypes.UINT8, nil, base.DEC, 0x8),
    cs       = ProtoField.new("CS", "egts.cs", ftypes.UINT8, nil, base.DEC, 0x4),
    fix      = ProtoField.new("FIX", "egts.fix", ftypes.UINT8, nil, base.DEC, 0x2),
    vld      = ProtoField.new("VLD", "egts.vld", ftypes.UINT8, nil, base.DEC, 0x1),
    dirh     = ProtoField.new("Direction the Highest bit", "egts.dirh", ftypes.UINT16, nil, base.DEC, 0x8000),
    alts     = ProtoField.new("Altitude sign", "egts.alts", ftypes.UINT16, nil, base.DEC, 0x4000),
    spd      = ProtoField.new("Speed", "egts.spd", ftypes.UINT16, nil, base.DEC, 0x3fff),
    dir      = ProtoField.new("Direction", "egts.dir", ftypes.UINT8, nil, base.DEC),
    odm      = ProtoField.new("Odometer", "egts.odm", ftypes.UINT32, nil, base.DEC),
    din      = ProtoField.new("Digital inputs", "egts.din", ftypes.UINT8, nil, base.DEC),
    src      = ProtoField.new("Source", "egts.src", ftypes.UINT8, nil, base.DEC),
    alt      = ProtoField.new("Altitude", "egts.alt", ftypes.UINT32, nil, base.DEC),
    srcd     = ProtoField.new("Source data", "egts.srcd", ftypes.UINT16, nil, base.DEC),
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

local function parse_sr_response(buf, tree)
    local cur_offset = 0

    tree:add(header.crn, buf:range(cur_offset, 2):le_uint())
    cur_offset = cur_offset + 2

    tree:add(header.rs, buf:range(cur_offset, 1):uint())
    cur_offset = cur_offset + 1
  
    return buf:len()
end

local function parse_sr_pos_data(buf, tree)
    local cur_offset = 0
    
    local ntm = buf:range(cur_offset, 4):le_uint()
    local offset_time = os.time{year=2010, month=1, day=1, hour=0}
    ntm = ntm + offset_time

    tree:add(header.ntm, NSTime.new(ntm))
    cur_offset = cur_offset + 4

    tree:add(header.lat, buf:range(cur_offset, 4):le_uint() * 90 / 0xFFFFFFFF)
    cur_offset = cur_offset + 4

    tree:add(header.long, buf:range(cur_offset, 4):le_uint() * 180 / 0xFFFFFFFF)
    cur_offset = cur_offset + 4

    local flg = buf:range(cur_offset, 1):uint()
    tree:add(header.alte, flg)
    tree:add(header.lohs, flg)
    tree:add(header.lahs, flg)
    tree:add(header.mv, flg)
    tree:add(header.bb, flg)
    tree:add(header.cs, flg)
    tree:add(header.fix, flg)
    tree:add(header.vld, flg)
    cur_offset = cur_offset + 1

    local spd = buf:range(cur_offset, 2):le_uint()
    tree:add(header.dirh, spd)
    tree:add(header.alts, spd)
    tree:add(header.vld, spd)
    cur_offset = cur_offset + 2

    tree:add(header.dir, buf:range(cur_offset, 1):uint())
    cur_offset = cur_offset + 1

    tree:add(header.odm, buf:range(cur_offset, 3):le_uint())
    cur_offset = cur_offset + 3

    tree:add(header.din, buf:range(cur_offset, 1):uint())
    cur_offset = cur_offset + 1

    tree:add(header.src, buf:range(cur_offset, 1):uint())
    cur_offset = cur_offset + 1

    if bit.band(flg, 0x80) ~= 0 then
        tree:add(header.alt, buf:range(cur_offset, 3):le_uint())
        cur_offset = cur_offset + 3
    end

    -- TODO: разобраться с разбором SourceData
    return buf:len()
end

local function parse_subrecord(buf, tree)
    local subrecords = tree:add(egts_proto, buf, "Record data")
    local current_offset = 0
    while current_offset < buf:len() do
        local subrecord = subrecords:add(egts_proto, buf, "Subrecord")
              
        local subrecord_type = buf:range(current_offset, 1):uint()
        subrecord:add(header.srt, subrecord_type)
        current_offset = current_offset + 1

        local subrecord_data_len = buf:range(current_offset, 2):le_uint()
        subrecord:add(header.srl, subrecord_data_len)
        current_offset = current_offset + 2  

        local sr_data = buf:range(current_offset, subrecord_data_len)
        local srd = subrecord:add(egts_proto, sr_data, "Subrecord data")
        
        if subrecord_type == 0 then
            parse_sr_response(sr_data, srd)
        elseif subrecord_type == 16 then
            parse_sr_pos_data(sr_data, srd)
        else
            subrecord:add(header.srd, sr_data:raw())
        end
      
        current_offset = current_offset + subrecord_data_len
    end

    return current_offset
end

local function parse_sdr(buf, tree)
    local current_offset = 0
    local sdr_len = 0
    while (current_offset < buf:len()) do
        sdr_len = buf:range(current_offset, 2):le_uint()
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

        local computed_bytes = parse_subrecord(buf:range(current_offset, sdr_len), service_data_record)
        current_offset = current_offset + computed_bytes
    end

    return current_offset
end

local function parse_pt_response (buf, tree)
    local current_offset = 0
    tree:add(header.rpid, buf:range(current_offset, 2):le_uint())
    current_offset = current_offset + 2

    tree:add(header.pr, buf:range(current_offset, 1):uint())
    current_offset = current_offset + 1

    local computed_bytes = parse_sdr(buf:range(current_offset), tree)
    current_offset = current_offset + computed_bytes

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
    tree:add(header.prt, prf_tvbr)

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

