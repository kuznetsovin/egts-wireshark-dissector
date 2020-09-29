-- создаем описание нового протокола
local egts_proto = Proto("egts", "EGTS")

-- настройки плагина
local default_settings =
{
    port = 20629

}

local header =
{
    
    version           = ProtoField.new("ProtocolVersion", "egts.prv", ftypes.UINT8, nil, base.DEC),
    security_key_id   = ProtoField.new("SecurityKeyID", "egts.skid", ftypes.UINT8, nil, base.DEC),
    prefix            = ProtoField.new("Prefix", "egts.prf", ftypes.UINT8, nil, base.DEC, 0xc0),
    route             = ProtoField.new("Route", "egts.rte", ftypes.UINT8, nil, base.DEC, 0x20),
    encryption_alg    = ProtoField.new("Encryption alg", "egts.ena", ftypes.UINT8, nil, base.DEC, 0x18),
    compression       = ProtoField.new("Compression", "egts.cmp", ftypes.UINT8, nil, base.DEC, 0x4),
    priority          = ProtoField.new("Priority", "egts.pr", ftypes.UINT8, nil, base.DEC, 0x3),
    header_length     = ProtoField.new("Header length", "egts.hl", ftypes.UINT8, nil, base.DEC),
    header_encoding   = ProtoField.new("Header encoding", "egts.he", ftypes.UINT8, nil, base.DEC),
    frame_data_length = ProtoField.new("Frame data length", "egts.fdl", ftypes.UINT16, nil, base.DEC),
    packet_identifier = ProtoField.new("Packet identifier", "egts.pid", ftypes.UINT16, nil, base.DEC),
    packet_type       = ProtoField.new("Packet type", "egts.pt", ftypes.UINT8, nil, base.DEC),
    peer_address      = ProtoField.new("Peer address", "egts.pra", ftypes.UINT16, nil, base.DEC),
    recipient_address = ProtoField.new("Recipient address", "egts.rca", ftypes.UINT16, nil, base.DEC),
    ttl               = ProtoField.new("Time to live", "egts.ttl", ftypes.UINT8, nil, base.DEC),
    header_checksum   = ProtoField.new("Header checksum", "egts.hcs", ftypes.UINT8, nil, base.HEX),    
    sfrd              = ProtoField.new("Services frame data", "egts.sfrd", ftypes.BYTES),    
    sfrcs             = ProtoField.new("Services frame data checksum", "egts.sfrcs", ftypes.UINT16, nil, base.HEX)
}

-- регистрация полей протокола
egts_proto.fields = header

-- задаем функию обработки, которая получает на вход данные tvbuf (объект Tvb), информацию о пакете 
-- pktinfo (объект Pinfo) и root дерево распарсенного объекта.
function egts_proto.dissector(tvbuf, pktinfo, root)    
    -- получаем размер буфера с пакетами.
    local pktlen = tvbuf:len()
    local bytes_consumed = 0

    -- запускаем цикл на чтение так как dissector запускается на один tcp сегмент, 
    -- а он может содержать несколько пакетов
    while bytes_consumed < pktlen do

        -- для одного EGTS пакета вызываем функцию парсинга
        local result = dissectEGTS(tvbuf, pktinfo, root, bytes_consumed)
        print("Result: " .. result)

        if result > 0 then
            -- функция парсинга отработала корректно и переход к следующему пакет
            bytes_consumed = bytes_consumed + result
            -- go again on another while loop
        elseif result == 0 then
            -- в процессе обработки произошла какая-то ошибка
            return 0
        else
            -- если вернулось отрицательное число значит не хватило данных и надо перейти в следующий сегмент
            pktinfo.desegment_offset = bytes_consumed
            result = -result
            pktinfo.desegment_len = result

            -- говорим что сегмент обработан удачно
            return pktlen
        end  
    end

    --  Для TCP нужно вернуть либо кол-во обработанных байт либо пустоту
    return bytes_consumed
end


dissectEGTS = function (tvbuf, pktinfo, root, offset)
    pktinfo.cols.protocol:set("EGTS")

    local actual_buf_len = tvbuf:len() - offset

    -- если сообщение меньше обязательного заголовка нужно перейти в следующий сегмент
    if actual_buf_len < 11 then
        return actual_buf_len - 11
    end

    -- получаем длину пакета
    local header_tvbr = tvbuf:range(offset + 3, 1)
    local header_len = header_tvbr:uint()
    local data_len_tvbr = tvbuf:range(offset + 5, 2)
    local data_len = data_len_tvbr:le_uint()

    local msglen = header_len + data_len

    -- если в бурефе не все сообщение нужно перейти на следующий сегмент
    if msglen > actual_buf_len then
        return actual_buf_len - msglen
    end

    -- Начинаем заполнения дерева в отображении
    local tree = root:add(egts_proto, tvbuf:range(offset, msglen))

    -- dissect the version field
    tree:add(header.version, tvbuf:range(offset, 1):uint())
    tree:add(header.security_key_id, tvbuf:range(offset + 1, 1):uint())

    local prf_tvbr = tvbuf:range(offset + 2, 1):uint()
    tree:add(header.prefix, prf_tvbr)
    tree:add(header.route, prf_tvbr)
    tree:add(header.encryption_alg, prf_tvbr)
    tree:add(header.compression, prf_tvbr)
    tree:add(header.priority, prf_tvbr)    

    tree:add(header.header_length, header_len)
    tree:add(header.header_encoding, tvbuf:range(offset + 4, 1):uint())
    tree:add(header.frame_data_length, data_len)
    tree:add(header.header_encoding, tvbuf:range(offset + 7, 1):uint())
    tree:add(header.packet_type, tvbuf:range(offset + 8, 1):uint())
    tree:add(header.header_checksum, tvbuf:range(offset + 9, 1):uint())

    local field_offset = 10;
    
    if bit.band(prf_tvbr, 0x20) == 1 then
        -- если RTE флаг присутствует, то заполняем не обязательные поля
        
        tree:add(header.peer_address, tvbuf:range(offset + field_offset, 2):raw())
        field_offset = field_offset + 2
        tree:add(header.recipient_address, tvbuf:range(offset + field_offset, 2):raw())
        field_offset = field_offset + 2
        tree:add(header.ttl, tvbuf:range(offset + field_offset, 1):raw())
        field_offset = field_offset + 1
    end

    tree:add(header.sfrd, tvbuf:range(offset + field_offset, data_len):raw())
    tree:add(header.sfrcs, tvbuf:range(offset + field_offset + data_len - 1, 2):uint())

    return msglen
end

-- добавляем парсер в таблицу
DissectorTable.get("tcp.port"):add(default_settings.port, egts_proto)