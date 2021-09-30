-- создаем описание нового протокола
local egts_proto = Proto("egts", "EGTS")

-- настройки плагина
local default_settings =
{
    port = 5020
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
    [1]  = "EGTS_SR_TERM_IDENTITY",
    [9]  = "EGTS_SR_RESULT_CODE",
    [15] = "EGTS_SR_EGTSPLUS_DATA",
    [16] = "EGTS_SR_POS_DATA",
    [17] = "EGTS_SR_EXT_POS_DATA",
    [18] = "EGTS_SR_AD_SENSORS_DATA",
    [19] = "EGTS_SR_COUNTERS_DATA",
    [20] = "EGTS_SR_STATE_DATA",
    [22] = "EGTS_SR_LOOPIN_DATA",
    [23] = "EGTS_SR_ABS_DIG_SENS_DATA",
    [24] = "EGTS_SR_ABS_AN_SENS_DATA",
    [25] = "EGTS_SR_ABS_CNTR_DATA",
    [26] = "EGTS_SR_ABS_LOOPIN_DATA",
    [27] = "EGTS_SR_LIQUID_LEVEL_SENSOR",
    [28] = "EGTS_SR_PASSENGERS_COUNTERS",
}

local result_code = {
    [0]   = "EGTS_PC_OK",
    [1]   = "EGTS_PC_IN_PROGRESS",
    [128] = "EGTS_PC_UNS_PROTOCOL",
    [129] = "EGTS_PC_DECRYPT_ERROR",
    [130] = "EGTS_PC_PROC_DENIED",
    [131] = "EGTS_PC_INC_HEADERFORM",
    [132] = "EGTS_PC_INC_DATAFORM",
    [133] = "EGTS_PC_UNS_TYPE",
    [134] = "EGTS_PC_NOTEN_PARAMS",
    [135] = "EGTS_PC_DBL_PROC",
    [136] = "EGTS_PC_PROC_SRC_DENIED",
    [137] = "EGTS_PC_HEADERCRC_ERROR",
    [138] = "EGTS_PC_DATACRC_ERROR",
    [139] = "EGTS_PC_INVDATALEN",
    [140] = "EGTS_PC_ROUTE_NFOUND",
    [141] = "EGTS_PC_ROUTE_CLOSED",
    [142] = "EGTS_PC_ROUTE_DENIED",
    [143] = "EGTS_PC_INVADDR",
    [144] = "EGTS_PC_TTLEXPIRED",
    [145] = "EGTS_PC_NO_ACK",
    [146] = "EGTS_PC_OBJ_NFOUND",
    [147] = "EGTS_PC_EVNT_NFOUND",
    [148] = "EGTS_PC_SRVC_NFOUND",
    [149] = "EGTS_PC_SRVC_DENIED",
    [150] = "EGTS_PC_SRVC_UNKN",
    [151] = "EGTS_PC_AUTH_DENIED",
    [152] = "EGTS_PC_ALREADY_EXISTS",
    [153] = "EGTS_PC_ID_NFOUND",
    [154] = "EGTS_PC_INC_DATETIME",
    [155] = "EGTS_PC_IO_ERROR",
    [156] = "EGTS_PC_NO_RES_AVAIL",
    [157] = "EGTS_PC_MODULE_FAULT",
    [158] = "EGTS_PC_MODULE_PWR_FLT",
    [159] = "EGTS_PC_MODULE_PROC_FLT",
    [160] = "EGTS_PC_MODULE_SW_FLT",
    [161] = "EGTS_PC_MODULE_FW_FLT",
    [162] = "EGTS_PC_MODULE_IO_FLT",
    [163] = "EGTS_PC_MODULE_MEM_FLT",
    [164] = "EGTS_PC_TEST_FAILED",
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
    srd      = ProtoField.new("Subrecord data", "egts.srd", ftypes.STRING),
    crn      = ProtoField.new("Confirmed record number", "egts.crn", ftypes.UINT16, nil, base.DEC),
    rs       = ProtoField.new("Record status", "egts.rs", ftypes.UINT8, result_code, base.DEC),
    tid      = ProtoField.new("Terminal identifier", "egts.tid", ftypes.UINT32, nil, base.DEC),
    mne      = ProtoField.new("MNE", "egts.mne", ftypes.UINT8, nil, base.DEC, 0x80),
    bse      = ProtoField.new("BSE", "egts.bse", ftypes.UINT8, nil, base.DEC, 0x40),
    nide     = ProtoField.new("NIDE", "egts.nide", ftypes.UINT8, nil, base.DEC, 0x20),
    ssra     = ProtoField.new("SSRA", "egts.ssra", ftypes.UINT8, nil, base.DEC, 0x10),
    lngce    = ProtoField.new("LNGCE", "egts.lngce", ftypes.UINT8, nil, base.DEC, 0x8),
    imsie    = ProtoField.new("IMSIE", "egts.imsie", ftypes.UINT8, nil, base.DEC, 0x4),
    imeie    = ProtoField.new("IMEIE", "egts.imeie", ftypes.UINT8, nil, base.DEC, 0x2),
    hdide    = ProtoField.new("HDIDE", "egts.hdide", ftypes.UINT8, nil, base.DEC, 0x1),
    hdid     = ProtoField.new("Home dispatcher identifier", "egts.hdid", ftypes.UINT16, nil, base.DEC),
    imei     = ProtoField.new("International mobile equipment identity", "egts.imei", ftypes.STRING),
    imsi     = ProtoField.new("International mobile subscriber identity", "egts.imsi", ftypes.STRING),
    lngc     = ProtoField.new("Language code", "egts.lngc", ftypes.STRING),
    nid      = ProtoField.new("Network identifier", "egts.nid", ftypes.UINT32, nil, base.DEC),
    bs       = ProtoField.new("Buffer size", "egts.bs", ftypes.UINT32, nil, base.DEC),
    msisdn   = ProtoField.new("Mobile station integrated services digital network number", "egts.msisdn", ftypes.STRING),
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
    nsfe     = ProtoField.new("NSFE", "egts.nsfe", ftypes.UINT8, nil, base.DEC, 0x10),
    sfe      = ProtoField.new("SFE", "egts.sfe", ftypes.UINT8, nil, base.DEC, 0x8),
    pfe      = ProtoField.new("PFE", "egts.pfe", ftypes.UINT8, nil, base.DEC, 0x4),
    hfe      = ProtoField.new("HFE", "egts.hfe", ftypes.UINT8, nil, base.DEC, 0x2),
    vfe      = ProtoField.new("VFE", "egts.vfe", ftypes.UINT8, nil, base.DEC, 0x1),
    vdop     = ProtoField.new("Vertical dilution of precision", "egts.vdop", ftypes.UINT16, nil, base.DEC),
    hdop     = ProtoField.new("Horizontal dilution of precision", "egts.hdop", ftypes.UINT16, nil, base.DEC),
    pdop     = ProtoField.new("Position dilution of precision", "egts.pdop", ftypes.UINT16, nil, base.DEC),
    sat      = ProtoField.new("Satellites", "egts.sat", ftypes.UINT8, nil, base.DEC),
    ns       = ProtoField.new("Navigation system", "egts.ns", ftypes.UINT16, nil, base.DEC),
    st       = ProtoField.new("State", "egts.ns", ftypes.UINT8, nil, base.DEC),
    mpsv     = ProtoField.new("Main power source voltage", "egts.mpsv", ftypes.UINT8, nil, base.DEC),
    bbv      = ProtoField.new("Back up battery voltage", "egts.bbv", ftypes.UINT8, nil, base.DEC),
    ibv      = ProtoField.new("Internal battery voltage", "egts.ibv", ftypes.UINT8, nil, base.DEC),
    nms      = ProtoField.new("NMS", "egts.nms", ftypes.UINT8, nil, base.DEC, 0x4),
    ibu      = ProtoField.new("IBU", "egts.ibu", ftypes.UINT8, nil, base.DEC, 0x2),
    bbu      = ProtoField.new("BBU", "egts.bbu", ftypes.UINT8, nil, base.DEC, 0x1),
    sfrcs    = ProtoField.new("Services frame data checksum", "egts.sfrcs", ftypes.UINT16, nil, base.HEX),
    llsef    = ProtoField.new("Liquid Level Sensor Error Flag", "egts.llsef", ftypes.UINT8, nil, base.DEC, 0x40),
    llsvu    = ProtoField.new("Liquid Level Sensor Value Unit", "egts.llsvu", ftypes.UINT8, nil, base.DEC, 0x30),
    rdf      = ProtoField.new("Raw Data Flag", "egts.rdf", ftypes.UINT8, nil, base.DEC, 0x8),
    llsn     = ProtoField.new("Liquid Level Sensor Number", "egts.llsn", ftypes.UINT8, nil, base.DEC, 0x7),
    maddr    = ProtoField.new("Module address", "egts.maddr", ftypes.UINT16, nil, base.DEC),
    llsd     = ProtoField.new("Liquid Level Sensor Data", "egts.llsd", ftypes.UINT32, nil, base.DEC),
    llsdraw  = ProtoField.new("Liquid Level Sensor Data bytes", "egts.llsdraw", ftypes.STRING),
    dioe1    = ProtoField.new("Digital Inputs Octet Exists 1", "egts.dioe1", ftypes.UINT8, nil, base.DEC, 0x1),
    dioe2    = ProtoField.new("Digital Inputs Octet Exists 2", "egts.dioe2", ftypes.UINT8, nil, base.DEC, 0x2),
    dioe3    = ProtoField.new("Digital Inputs Octet Exists 3", "egts.dioe3", ftypes.UINT8, nil, base.DEC, 0x4),
    dioe4    = ProtoField.new("Digital Inputs Octet Exists 4", "egts.dioe4", ftypes.UINT8, nil, base.DEC, 0x8),
    dioe5    = ProtoField.new("Digital Inputs Octet Exists 5", "egts.dioe5", ftypes.UINT8, nil, base.DEC, 0x10),
    dioe6    = ProtoField.new("Digital Inputs Octet Exists 6", "egts.dioe6", ftypes.UINT8, nil, base.DEC, 0x20),
    dioe7    = ProtoField.new("Digital Inputs Octet Exists 7", "egts.dioe7", ftypes.UINT8, nil, base.DEC, 0x40),
    dioe8    = ProtoField.new("Digital Inputs Octet Exists 8", "egts.dioe8", ftypes.UINT8, nil, base.DEC, 0x80),
    dout     = ProtoField.new("Digital Outputs", "egts.dout", ftypes.UINT8, nil, base.DEC),
    asfe1    = ProtoField.new("Analog Sensor Fields Exist 1", "egts.asfe1", ftypes.UINT8, nil, base.DEC, 0x1),
    asfe2    = ProtoField.new("Analog Sensor Fields Exist 2", "egts.asfe2", ftypes.UINT8, nil, base.DEC, 0x2),
    asfe3    = ProtoField.new("Analog Sensor Fields Exist 3", "egts.asfe3", ftypes.UINT8, nil, base.DEC, 0x4),
    asfe4    = ProtoField.new("Analog Sensor Fields Exist 4", "egts.asfe4", ftypes.UINT8, nil, base.DEC, 0x8),
    asfe5    = ProtoField.new("Analog Sensor Fields Exist 5", "egts.asfe5", ftypes.UINT8, nil, base.DEC, 0x10),
    asfe6    = ProtoField.new("Analog Sensor Fields Exist 6", "egts.asfe6", ftypes.UINT8, nil, base.DEC, 0x20),
    asfe7    = ProtoField.new("Analog Sensor Fields Exist 7", "egts.asfe7", ftypes.UINT8, nil, base.DEC, 0x40),
    asfe8    = ProtoField.new("Analog Sensor Fields Exist 8", "egts.asfe8", ftypes.UINT8, nil, base.DEC, 0x80),
    adio1    = ProtoField.new("Additional Digital Inputs Octet 1", "egts.adio1", ftypes.UINT8, nil, base.DEC),
    adio2    = ProtoField.new("Additional Digital Inputs Octet 2", "egts.adio2", ftypes.UINT8, nil, base.DEC),
    adio3    = ProtoField.new("Additional Digital Inputs Octet 3", "egts.adio3", ftypes.UINT8, nil, base.DEC),
    adio4    = ProtoField.new("Additional Digital Inputs Octet 4", "egts.adio4", ftypes.UINT8, nil, base.DEC),
    adio5    = ProtoField.new("Additional Digital Inputs Octet 5", "egts.adio5", ftypes.UINT8, nil, base.DEC),
    adio6    = ProtoField.new("Additional Digital Inputs Octet 6", "egts.adio6", ftypes.UINT8, nil, base.DEC),
    adio7    = ProtoField.new("Additional Digital Inputs Octet 7", "egts.adio7", ftypes.UINT8, nil, base.DEC),
    adio8    = ProtoField.new("Additional Digital Inputs Octet 8", "egts.adio8", ftypes.UINT8, nil, base.DEC),
    ans1     = ProtoField.new("Analog Sensor 1", "egts.ans1", ftypes.UINT16, nil, base.DEC),
    ans2     = ProtoField.new("Analog Sensor 2", "egts.ans2", ftypes.UINT16, nil, base.DEC),
    ans3     = ProtoField.new("Analog Sensor 3", "egts.ans3", ftypes.UINT16, nil, base.DEC),
    ans4     = ProtoField.new("Analog Sensor 4", "egts.ans4", ftypes.UINT16, nil, base.DEC),
    ans5     = ProtoField.new("Analog Sensor 5", "egts.ans5", ftypes.UINT16, nil, base.DEC),
    ans6     = ProtoField.new("Analog Sensor 6", "egts.ans6", ftypes.UINT16, nil, base.DEC),
    ans7     = ProtoField.new("Analog Sensor 7", "egts.ans7", ftypes.UINT16, nil, base.DEC),
    ans8     = ProtoField.new("Analog Sensor 8", "egts.ans8", ftypes.UINT16, nil, base.DEC),
    cn       = ProtoField.new("Counter Number", "egts.cn", ftypes.UINT8, nil, base.DEC),
    cnv      = ProtoField.new("Counter Value", "egts.cnv", ftypes.UINT16, nil, base.DEC),
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

local function parse_sr_term_identity(buf, tree)
    local cur_offset = 0

    tree:add(header.tid, buf:range(cur_offset, 4):le_uint())
    cur_offset = cur_offset + 4

    local flags = buf:range(cur_offset, 1):le_uint()
    tree:add(header.mne, flags)
    tree:add(header.bse, flags)
    tree:add(header.nide, flags)
    tree:add(header.ssra, flags)
    tree:add(header.lngce, flags)
    tree:add(header.imsie, flags)
    tree:add(header.imeie, flags)
    tree:add(header.hdide, flags)
    cur_offset = cur_offset + 1

    if bit.band(flags, 0x1) ~= 0 then
        tree:add(header.hdid, buf:range(cur_offset, 2):uint())
        cur_offset = cur_offset + 2
    end

    if bit.band(flags, 0x2) ~= 0 then
        tree:add(header.imei, buf:range(cur_offset, 15):string())
        cur_offset = cur_offset + 15
    end

    if bit.band(flags, 0x4) ~= 0 then
        tree:add(header.imsi, buf:range(cur_offset, 16):string())
        cur_offset = cur_offset + 16
    end

    if bit.band(flags, 0x8) ~= 0 then
        tree:add(header.lngc, buf:range(cur_offset, 3):string())
        cur_offset = cur_offset + 3
    end

    if bit.band(flags, 0x20) ~= 0 then
        tree:add(header.nid, buf:range(cur_offset, 3):le_uint())
        cur_offset = cur_offset + 3
    end

    if bit.band(flags, 0x40) ~= 0 then
        tree:add(header.bs, buf:range(cur_offset, 2):le_uint())
        cur_offset = cur_offset + 2
    end

    if bit.band(flags, 0x80) ~= 0 then
        tree:add(header.msisdn, buf:range(cur_offset, 15):le_uint())
        cur_offset = cur_offset + 15
    end

    return cur_offset
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
    tree:add(header.spd, spd)
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

local function parse_sr_ext_pos_data(buf, tree)
    local cur_offset = 0
    local flags = buf:range(cur_offset, 1):uint()
    tree:add(header.nsfe, flags)
    tree:add(header.sfe, flags)
    tree:add(header.pfe, flags)
    tree:add(header.hfe, flags)
    tree:add(header.vfe, flags)
    cur_offset = cur_offset + 1

    if bit.band(flags, 0x1) ~= 0 then
        -- если флаг VFE установлен, то есть поле снижение точности в вертикальной плоскости
        tree:add(header.vdop, buf:range(cur_offset, 2):le_uint())
        cur_offset = cur_offset + 2
    end

    if bit.band(flags, 0x2) ~= 0 then
        -- если флаг HFE установлен, то есть поле снижение точности в горизонтальной плоскости
        tree:add(header.hdop, buf:range(cur_offset, 2):le_uint())
        cur_offset = cur_offset + 2
    end

    if bit.band(flags, 0x4) ~= 0 then
        -- если флаг HFE установлен, то есть поле снижение точности по местоположению
        tree:add(header.pdop, buf:range(cur_offset, 2):le_uint())
        cur_offset = cur_offset + 2
    end

    local sectionLen = buf:len()
    if bit.band(flags, 0x8) ~= 0 then
        -- если флаг SFE установлен, то есть поле c данными о текущем количестве видимых спутников и типе используемой навигационной спутниковой системы
        tree:add(header.sat, buf:range(cur_offset, 1):uint())
        cur_offset = cur_offset + 1

        if cur_offset < sectionLen then
            tree:add(header.ns, buf:range(cur_offset, 2):le_uint())
            cur_offset = cur_offset + 2
        end
    end

    return sectionLen
end

local function parse_sr_state_data(buf, tree)
    local cur_offset = 0

    tree:add(header.st, buf:range(cur_offset, 1):uint())
    cur_offset = cur_offset + 1
    
    tree:add(header.mpsv, buf:range(cur_offset, 1):uint())
    cur_offset = cur_offset + 1

    tree:add(header.bbv, buf:range(cur_offset, 1):uint())
    cur_offset = cur_offset + 1

    tree:add(header.ibv, buf:range(cur_offset, 1):uint())
    cur_offset = cur_offset + 1

    local flags = buf:range(cur_offset, 1):uint()
    tree:add(header.nms, flags)
    tree:add(header.ibu, flags)
    tree:add(header.bbu, flags)
    cur_offset = cur_offset + 1

    return cur_offset
end

local function parse_sr_liquid_level_sensor(buf, tree)
    local cur_offset = 0

    local flags = buf:range(cur_offset, 1):uint()
    tree:add(header.llsef, flags)
    tree:add(header.llsvu, flags)
    tree:add(header.rdf, flags)
    tree:add(header.llsn, flags)
    cur_offset = cur_offset + 1

    tree:add(header.maddr, buf:range(cur_offset, 2):le_uint())
    cur_offset = cur_offset + 2

    if bit.band(flags, 0x8) == 0 then
        -- если флаг RDF флаг установлен, то значение имеет длину 4 байта
        tree:add(header.llsd, buf:range(cur_offset, 4):le_uint())
        cur_offset = cur_offset + 4
    else
        tree:add(header.llsdraw, buf:bytes():tohex())
    end

    return cur_offset
end

local function parse_sr_ad_sensors_data(buf, tree)
    local cur_offset = 0
    local sectionLen = buf:len()

    local diflg = buf:range(cur_offset, 1):uint()
    tree:add(header.dioe1, diflg)
    tree:add(header.dioe2, diflg)
    tree:add(header.dioe3, diflg)
    tree:add(header.dioe4, diflg)
    tree:add(header.dioe5, diflg)
    tree:add(header.dioe6, diflg)
    tree:add(header.dioe7, diflg)
    tree:add(header.dioe8, diflg)
    cur_offset = cur_offset + 1

    tree:add(header.dout, buf:range(cur_offset, 1):uint())
    cur_offset = cur_offset + 1

    local ansflg = buf:range(cur_offset, 1):uint()
    tree:add(header.asfe1, ansflg)
    tree:add(header.asfe2, ansflg)
    tree:add(header.asfe3, ansflg)
    tree:add(header.asfe4, ansflg)
    tree:add(header.asfe5, ansflg)
    tree:add(header.asfe6, ansflg)
    tree:add(header.asfe7, ansflg)
    tree:add(header.asfe8, ansflg)
    cur_offset = cur_offset + 1

    if bit.band(diflg, 0x1) ~= 0 then
        tree:add(header.adio1, buf:range(cur_offset, 1):uint())
        cur_offset = cur_offset + 1
    end

    if bit.band(diflg, 0x2) ~= 0 then
        tree:add(header.adio2, buf:range(cur_offset, 1):uint())
        cur_offset = cur_offset + 1
    end

    if bit.band(diflg, 0x4) ~= 0 then
        tree:add(header.adio3, buf:range(cur_offset, 1):uint())
        cur_offset = cur_offset + 1
    end

    if bit.band(diflg, 0x8) ~= 0 then
        tree:add(header.adio4, buf:range(cur_offset, 1):uint())
        cur_offset = cur_offset + 1
    end

    if bit.band(diflg, 0x10) ~= 0 then
        tree:add(header.adio5, buf:range(cur_offset, 1):uint())
        cur_offset = cur_offset + 1
    end

    if bit.band(diflg, 0x20) ~= 0 then
        tree:add(header.adio6, buf:range(cur_offset, 1):uint())
        cur_offset = cur_offset + 1
    end

    if bit.band(diflg, 0x40) ~= 0 then
        tree:add(header.adio7, buf:range(cur_offset, 1):uint())
        cur_offset = cur_offset + 1
    end

    if bit.band(diflg, 0x80) ~= 0 then
        tree:add(header.adio8, buf:range(cur_offset, 1):uint())
        cur_offset = cur_offset + 1
    end

    if bit.band(ansflg, 0x1) ~= 0 then
        tree:add(header.ans1, buf:range(cur_offset, 3):le_uint())
        cur_offset = cur_offset + 3
    end

    if bit.band(ansflg, 0x2) ~= 0 then
        tree:add(header.ans2, buf:range(cur_offset, 3):le_uint())
        cur_offset = cur_offset + 3
    end

    if bit.band(ansflg, 0x4) ~= 0 then
        tree:add(header.ans3, buf:range(cur_offset, 3):le_uint())
        cur_offset = cur_offset + 3
    end

    if bit.band(ansflg, 0x8) ~= 0 then
        tree:add(header.ans4, buf:range(cur_offset, 3):le_uint())
        cur_offset = cur_offset + 3
    end

    if bit.band(ansflg, 0x10) ~= 0 then
        tree:add(header.ans5, buf:range(cur_offset, 3):le_uint())
        cur_offset = cur_offset + 3
    end

    if bit.band(ansflg, 0x20) ~= 0 then
        tree:add(header.ans6, buf:range(cur_offset, 3):le_uint())
        cur_offset = cur_offset + 3
    end

    if bit.band(ansflg, 0x40) ~= 0 then
        tree:add(header.ans7, buf:range(cur_offset, 3):le_uint())
        cur_offset = cur_offset + 3
    end

    if bit.band(ansflg, 0x80) ~= 0 then
        tree:add(header.ans8, buf:range(cur_offset, 3):le_uint())
        cur_offset = cur_offset + 3
    end

    return sectionLen
end

local function parse_sr_abs_cntr_data(buf, tree)
    local cur_offset = 0

    tree:add(header.cnv, buf:range(cur_offset, 1):uint())
    cur_offset = cur_offset + 1

    tree:add(header.cnv, buf:range(cur_offset, 3):le_uint())
    cur_offset = cur_offset + 3

    return offset
end

local function parse_sr_result_code(buf, tree)
    local cur_offset = 0

    tree:add(header.rs, buf:range(cur_offset, 1):uint())
    cur_offset = cur_offset + 1
  
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
        elseif subrecord_type == 1 then
            parse_sr_term_identity(sr_data, srd)
        elseif subrecord_type == 9 then
            parse_sr_result_code(sr_data, srd)
        elseif subrecord_type == 16 then
            parse_sr_pos_data(sr_data, srd)
        elseif subrecord_type == 17 then
            parse_sr_ext_pos_data(sr_data, srd)
        elseif subrecord_type == 20 then
            parse_sr_state_data(sr_data, srd)
        elseif subrecord_type == 27 then
            parse_sr_liquid_level_sensor(sr_data, srd)
        elseif subrecord_type == 18 then
            parse_sr_ad_sensors_data(sr_data, srd)
        elseif subrecord_type == 25 then
            parse_sr_abs_cntr_data(sr_data, srd)
        else
            subrecord:add(header.srd, sr_data:bytes():tohex())
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

    if buf:len() - current_offset > 0 then
        local computed_bytes = parse_sdr(buf:range(current_offset), tree)
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

