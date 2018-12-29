#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

import struct
from scapy.fields import ByteEnumField, StrField, ConditionalField, \
    BitEnumField, BitField, XByteField, FieldListField, \
    XShortField, X3BytesField, XIntField, ByteField, \
    ShortField, ObservableDict, XShortEnumField, XByteEnumField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import TCP, UDP

"""
DoIP
"""


class DoIP(Packet):
    payload_types = {
        0x0000: "generic DoIP header negative acknowledge",
        0x0001: "vehicle identification request message",
        0x0002: "vehicle identification request",
        0x0003: "vehicle identification request message with VIN",
        0x0004: "Vehicle announcement message/vehicle identification response",
        0x0005: "routing activation request",
        0x0006: "routing activation response",
        0x0007: "alive check request",
        0x0008: "alive check response",
        0x4001: "DoIP entity status request",
        0x4002: "DoIP entity status response",
        0x4003: "diagnostic power mode information request",
        0x4004: "diagnostic power mode information response",
        0x8001: "diagnostic message",
        0x8002: "Diagnostic message positive acknowledgement",
        0x8003: "diagnostic message negative acknowledgement"}
    name = 'DoIP'
    fields_desc = [
        XByteField("protocol_version", 0x02),
        XByteField("inverse_version", 0xFD),
        XShortEnumField("payload_type", 0, payload_types),
        IntField("payload_length", 0)
    ]

    def answers(self, other):
        """DEV: true if self is an answer from other"""
        if other.__class__ == self.__class__:
            return "TODO: depends on payload type"
        return 0

    def hashret(self):
        if self.service == 0x7f:
            return struct.pack('B', self.requestServiceId)
        return struct.pack('B', self.service & ~0x40)


bind_layers(UDP, DoIP, sport=13400)
bind_layers(UDP, DoIP, dport=13400)
bind_layers(TCP, DoIP, sport=13400)
bind_layers(TCP, DoIP, dport=13400)
