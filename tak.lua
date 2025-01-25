-- TAK Protocol Plugin

-- NOTE: Lua plugins cannot automatically modify the Protobuf search paths yet.
-- See the issue here: https://gitlab.com/wireshar/wireshark/-/issues/19394

-- Metadata
set_plugin_info({
    description = "Wireshark plugin for TAK/COT protocol.",
    author      = "Joshua M. Keyes <joshua.michael.keyes@gmail.com>",
    repository  = "https://github.com/jmkeyes/wireshark-tak-plugin",
    version     = "1.0.0",
})

-- Default settings.
local default_settings = {
    -- The port number to associate with TAK messages.
    port         = 6969,
    -- The protobuf message name to decode from the buffer.
    message_type = "atakmap.commoncommo.protobuf.v1.TakMessage"
}

-- Decode a TAK protocol spec varint.
local function varint(buffer, offset)
    local index = 0
    local value = 0

    while true do
        -- Get the next byte in the buffer.
        local byte = buffer:range(offset + index, 1):uint()

        -- Accumulate the lower seven bits of this byte.
        value = value + bit.lshift(bit.band(byte, 0x7f), index * 7)

        -- Exit if the most significant bit was not set.
        if bit.band(byte, 0x80) == 0 then
            break
        end

        -- Advance the index.
        index = index + 1
    end

    -- Return the total value and byte count.
    return value, (index + 1)
end

-- Protocol definition.
tak = Proto("TAK", "TAK Protocol")

-- Protocol preferences.
tak.prefs.port         = Pref.uint("Port number", default_settings.port, "TCP/UDP port number.")
tak.prefs.message_type = Pref.string("Message Type", default_settings.message_type, "Protobuf message type.")

-- Protocol preference change callback.
tak.prefs_changed = function ()
    -- Reassociate the DissectorTable entry if using a non-default port.
    if default_settings.port ~= tak.prefs.port then
        -- Dissociate the TAK protocol from any non-default port.
        if default_settings.port ~= 0 then
            DissectorTable.get("tcp.port"):remove(default_settings.port, tak)
            DissectorTable.get("udp.port"):remove(default_settings.port, tak)
        end

        -- Reassign the default port to our preferred port.
        default_settings.port = tak.prefs.port

        -- Assocate the TAK protocol with the current port.
        if default_settings.port ~= 0 then
            DissectorTable.get("tcp.port"):add(default_settings.port, tak)
            DissectorTable.get("udp.port"):add(default_settings.port, tak)
        end
    end

    -- Set the Protobuf message type we should decode.
    default_settings.message_type = tak.message_type
end

-- Protocol fields.
tak.fields.protocol = ProtoField.string("tak.protocol", "Protocol")
tak.fields.version  = ProtoField.uint8("tak.version", "Version", base.DEC)
tak.fields.length   = ProtoField.uint32("tak.length", "Length", base.DEC)

-- Protocol expert information.
tak.experts.malformed = ProtoExpert.new("tak.expert.malformed", "Malformed TAK Message", expert.group.MALFORMED, expert.severity.ERROR)

-- Protocol dissector callback.
tak.dissector = function (buffer, pinfo, tree)
    local offset = 0
    local length = buffer:reported_length_remaining()
    local subtree = tree:add(tak, buffer:range(0, length), "TAK Message")

    -- Assign this packet our protocol name.
    pinfo.cols.protocol:set(tak.name)

    -- If this is an XML COT message then process it immediately.
    if buffer:range(offset, 5):string() == "<?xml" then
        local version = 0
        local protocol = "xml"

        -- If it's an XML payload then it's implicitly version 0.
        subtree:add(tak.fields.version, version)
        subtree:append_text((", Version: %d"):format(version))

        subtree:add(tak.fields.length, length)
        subtree:append_text((", Length: %d"):format(length))

        subtree:add(tak.fields.protocol, protocol)
        subtree:append_text((", Protocol: %s"):format(protocol))

        -- Build a TVB over the remaining bytes.
        local message = buffer:range(offset, length)
        return Dissector.get('xml'):call(message:tvb(), pinfo, subtree)
    end

    -- First byte must be 0xBF for this to be a TAK message.
    if buffer:range(offset, 1):uint() ~= 0xBF then
        subtree:add_proto_expert_info(tak.experts.malformed, "No magic byte!")
        return
    end

    -- Advance the offset ahead of the first magic byte.
    offset = offset + 1

    -- Decide a varint, which can be a message length or a version.
    local varint, varint_length = varint(buffer, offset)

    -- Advance the offset ahead of the decoded varint.
    offset = offset + varint_length

    -- Determine if the next byte is a magic (0xBF) byte.
    if buffer:range(offset, 1):uint() ~= 0xBF then
        local version = 1
        local protocol = "stream"
        local payload_length = varint

        -- If the payload length doesn't match the buffer length...
        if payload_length ~= (length - offset) then
            subtree:add_proto_expert_info(tak.experts.malformed, "Payload length mismatch!")
            return
        end

        -- The version is set implicitly for the streaming protocol.
        subtree:add(tak.fields.version, version)
        subtree:append_text((", Version: %d"):format(version))

        subtree:add(tak.fields.length, payload_length)
        subtree:append_text((", Length: %d"):format(payload_length))

        subtree:add(tak.fields.protocol, protocol)
        subtree:append_text((", Protocol: %s"):format(protocol))
    else
        -- Set the protocol version to the decided varint.
        local version = buffer:range(offset - 1, varint_length)
        subtree:add(tak.fields.version, version, varint)
        subtree:append_text((", Version: %d"):format(varint))

        -- Advance beyond the second magic byte.
        offset = offset + 1

        -- The payload length is the remaining buffer.
        local payload_length = length - offset
        subtree:add(tak.fields.length, payload_length)
        subtree:append_text((", Length: %d"):format(payload_length))

        -- This is a mesh protocol message.
        local protocol = "mesh"
        subtree:add(tak.fields.protocol, protocol)
        subtree:append_text((", Protocol: %s"):format(protocol))
    end

    -- Record the original packet information.
    local original_info = tostring(pinfo.cols.info)

    -- Calculate the remaining message length.
    local message = buffer:range(offset, length - offset):tvb()

    -- Hardcode the Protobuf dissector to interpret these packets as TakMessages.
    pinfo.private["pb_msg_type"] = ("message,%s"):format(default_settings.message_type)

    -- Parse the remaining message with the customized Protobuf dissector.
    local result = Dissector.get("protobuf"):call(message, pinfo, subtree)

    -- Wireshark <= 4.2.x protobuf dissector overrides the protocol instead of appending to it; this is fixed in the master branch.
    -- See: https://gitlab.com/wireshark/wireshark/-/blob/release-4.2/epan/dissectors/packet-protobuf.c?ref_type=headers#L1445-L1446
    pinfo.cols.protocol:prepend(tak.name .. "/")

    -- Restore the original packet information.
    pinfo.cols.info:prepend(original_info)

    return result
end

-- Associate the dissector to this preferred port.
DissectorTable.get("tcp.port"):add(default_settings.port, tak)
DissectorTable.get("udp.port"):add(default_settings.port, tak)
