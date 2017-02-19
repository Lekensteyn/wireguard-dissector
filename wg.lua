local proto_wg = Proto.new("wg", "WireGuard")
local type_names = {
    [1] = "Handshake Initiation",
    [2] = "Handshake Response",
    [3] = "Cookie Reply",
    [4] = "Transport Data",
}
local F = {
    type        = ProtoField.uint8("wg.type", "Type", base.DEC, type_names),
    reserved    = ProtoField.none("wg.reserved", "Reserved"),
    sender      = ProtoField.uint32("wg.sender", "Sender", base.HEX),
    ephemeral   = ProtoField.bytes("wg.ephemeral", "Ephemeral"),
    static      = ProtoField.bytes("wg.static", "Static"),
    timestamp   = ProtoField.bytes("wg.timestamp", "Timestamp"),
    mac1        = ProtoField.bytes("wg.mac1", "mac1"),
    mac2        = ProtoField.bytes("wg.mac2", "mac2"),
    receiver    = ProtoField.uint32("wg.receiver", "Receiver", base.HEX),
    empty       = ProtoField.bytes("wg.empty", "Empty"),
    nonce       = ProtoField.bytes("wg.nonce", "Nonce"),
    cookie      = ProtoField.bytes("wg.cookie", "Cookie"),
    counter     = ProtoField.uint64("wg.counter", "Counter"),
    packet      = ProtoField.bytes("wg.packet", "Packet"),
}
proto_wg.fields = F

-- Convenience function for consuming part of the buffer and remembering the
-- offset for the next time.
function next_tvb(tvb)
    local offset = 0
    return setmetatable({
        -- Returns the current offset.
        offset = function()
            return offset
        end,
    }, {
        -- Returns the TVB with the requested length
        __call = function(self, len)
            local t = tvb(offset, len)
            offset = offset + len
            return t
        end,
    })
end

function dissect_initiator(tvb, pinfo, tree)
    local t = next_tvb(tvb)
    tree:add(F.type,        t(1))
    tree:add(F.reserved,    t(3))
    tree:add(F.sender,      t(4))
    tree:add(F.ephemeral,   t(32))
    tree:add(F.static,      t(16+32)) -- 16 is AEAD tag length
    tree:add(F.timestamp,   t(16+12))
    tree:add(F.mac1,        t(16))
    tree:add(F.mac2,        t(16))
    return t:offset()
end

function dissect_responder(tvb, pinfo, tree)
    local t = next_tvb(tvb)
    tree:add(F.type,        t(1))
    tree:add(F.reserved,    t(3))
    tree:add(F.sender,      t(4))
    tree:add(F.receiver,    t(4))
    tree:add(F.ephemeral,   t(32))
    tree:add(F.empty,       t(16+0)) -- AEAD
    tree:add(F.mac1,        t(16))
    tree:add(F.mac2,        t(16))
    return t:offset()
end

function dissect_cookie(tvb, pinfo, tree)
    local t = next_tvb(tvb)
    tree:add(F.type,        t(1))
    tree:add(F.reserved,    t(3))
    tree:add(F.receiver,    t(4))
    tree:add(F.nonce,       t(24))
    tree:add(F.cookie,      t(16+16)) -- AEAD
    return t:offset()
end

function dissect_data(tvb, pinfo, tree)
    local t = next_tvb(tvb)
    tree:add(F.type,        t(1))
    tree:add(F.reserved,    t(3))
    tree:add(F.counter,     t(8))
    local packet_length = tvb:len() - t:offset() -- length includes AEAD tag
    tree:add(F.packet,      t(packet_length))
    return t:offset()
end

local types = {
    [1] = dissect_initiator,
    [2] = dissect_responder,
    [3] = dissect_cookie,
    [4] = dissect_data,
}

function proto_wg.dissector(tvb, pinfo, tree)
    if tvb:len() < 4 then return 0 end
    local type_val = tvb(0,1):uint()
    -- "Reserved" must be zero at the moment
    if tvb(1,3):uint() ~= 0 then return 0 end

    local subdissector = types[type_val]
    if not subdissector then return 0 end

    pinfo.cols.protocol = "WireGuard"
    pinfo.cols.info = type_names[type_val]
    local subtree = tree:add(proto_wg, tvb())
    -- TODO if this fails, heuristics dissector will fail as well. Expert info?
    return subdissector(tvb, pinfo, subtree)
end

proto_wg:register_heuristic("udp", proto_wg.dissector)
