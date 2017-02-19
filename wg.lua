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
    mac1        = ProtoField.bytes("wg.mac1", "mac1"),
    mac2        = ProtoField.bytes("wg.mac2", "mac2"),
    receiver    = ProtoField.uint32("wg.receiver", "Receiver", base.HEX),
    nonce       = ProtoField.bytes("wg.nonce", "Nonce"),
    cookie      = ProtoField.bytes("wg.cookie", "Cookie"),
    counter     = ProtoField.uint64("wg.counter", "Counter"),
}
local function add_aead_field(F, name, label)
    F[name] = ProtoField.none("wg." .. name, label .. " (encrypted)")
    -- The "empty" field does not have data, do not bother adding fields for it.
    if name ~= "empty" then
        F[name .. "_ciphertext"] = ProtoField.bytes("wg." .. name .. ".ciphertext", "Ciphertext")
        F[name .. "_data"] = ProtoField.bytes("wg." .. name .. ".data", label)
    end
    F[name .. "_atag"] = ProtoField.bytes("wg." .. name .. ".auth_tag", "Auth Tag")
end
add_aead_field(F, "static", "Static")
add_aead_field(F, "timestamp", "Timestamp")
add_aead_field(F, "empty", "Empty")
add_aead_field(F, "packet", "Packet")
proto_wg.fields = F

local efs = {}
efs.error               = ProtoExpert.new("wg.expert.error", "Dissection Error",
    expert.group.MALFORMED, expert.severity.ERROR)
efs.bad_packet_length   = ProtoExpert.new("wg.expert.bad_packet_length", "Packet length is too small!",
    expert.group.MALFORMED, expert.severity.ERROR)
proto_wg.experts = efs

-- Length of AEAD authentication tag
local AUTH_TAG_LENGTH = 16

-- Convenience function for consuming part of the buffer and remembering the
-- offset for the next time.
function next_tvb(tvb)
    local offset = 0
    return setmetatable({
        -- Returns the current offset.
        offset = function()
            return offset
        end,
        -- Returns the TVB with the requested length without advancing offset
        peek = function(self, len)
            local t = tvb(offset, len)
            self.tvb = t
            return t
        end,
    }, {
        -- Returns the TVB with the requested length
        __call = function(self, len)
            local t = tvb(offset, len)
            offset = offset + len
            self.tvb = t
            return t
        end,
    })
end

local function dissect_aead(t, tree, datalen, fieldname)
    -- Builds a tree:
    -- * Foo (Encrypted)
    --   * Ciphertext
    --   * XXX add decrypted field (or show it after the subtree)
    --   * Auth Tag
    local subtree = tree:add(F[fieldname], t:peek(datalen + AUTH_TAG_LENGTH))
    if datalen > 0 then
        subtree:add(F[fieldname .. "_ciphertext"], t(datalen))
        -- TODO add decryption
    end
    subtree:add(F[fieldname .. "_atag"], t(AUTH_TAG_LENGTH))
end

function dissect_initiator(tvb, pinfo, tree)
    local t = next_tvb(tvb)
    tree:add(F.type,        t(1))
    tree:add(F.reserved,    t(3))
    tree:add(F.sender,      t(4))
    pinfo.cols.info:append(string.format(", sender=0x%08X", t.tvb:uint()))
    tree:add(F.ephemeral,   t(32))
    dissect_aead(t, tree, 32, "static")
    dissect_aead(t, tree, 12, "timestamp")
    tree:add(F.mac1,        t(16))
    tree:add(F.mac2,        t(16))
    return t:offset()
end

function dissect_responder(tvb, pinfo, tree)
    local t = next_tvb(tvb)
    tree:add(F.type,        t(1))
    tree:add(F.reserved,    t(3))
    tree:add(F.sender,      t(4))
    pinfo.cols.info:append(string.format(", sender=0x%08X", t.tvb:uint()))
    tree:add(F.receiver,    t(4))
    pinfo.cols.info:append(string.format(", receiver=0x%08X", t.tvb:uint()))
    tree:add(F.ephemeral,   t(32))
    dissect_aead(t, tree, 0, "empty")
    tree:add(F.mac1,        t(16))
    tree:add(F.mac2,        t(16))
    return t:offset()
end

function dissect_cookie(tvb, pinfo, tree)
    local t = next_tvb(tvb)
    tree:add(F.type,        t(1))
    tree:add(F.reserved,    t(3))
    tree:add(F.receiver,    t(4))
    pinfo.cols.info:append(string.format(", receiver=0x%08X", t.tvb:uint()))
    tree:add(F.nonce,       t(24))
    dissect_aead(t, tree, 16, "cookie")
    return t:offset()
end

function dissect_data(tvb, pinfo, tree)
    local t = next_tvb(tvb)
    tree:add(F.type,        t(1))
    tree:add(F.reserved,    t(3))
    tree:add(F.receiver,    t(4))
    pinfo.cols.info:append(string.format(", receiver=0x%08X", t.tvb:uint()))
    tree:add_le(F.counter,  t(8))
    pinfo.cols.info:append(string.format(", counter=%s", t.tvb:le_uint64()))
    local packet_length = tvb:len() - t:offset()
    if packet_length < AUTH_TAG_LENGTH then
        -- Should not happen, it is a malformed packet.
        tree:add_tvb_expert_info(efs.bad_packet_length. t(packet_length))
        return t:offset()
    end
    local datalen = packet_length - AUTH_TAG_LENGTH
    if datalen > 0 then
        pinfo.cols.info:append(string.format(", datalen=%s", datalen))
    end
    dissect_aead(t, tree, datalen, "packet")
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
    local success, ret = pcall(subdissector, tvb, pinfo, subtree)
    if success then
        return ret
    else
        -- An error has occurred... Do not propagate it since Wireshark would
        -- then try a different heuristics dissectors.
        subtree:add_proto_expert_info(efs.error, ret)
        return tvb:len()
    end
end

proto_wg:register_heuristic("udp", proto_wg.dissector)
