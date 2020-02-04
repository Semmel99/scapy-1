# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = Unified Diagnostic Service (UDS)
# scapy.contrib.status = loads

import struct
import random

from collections import defaultdict, namedtuple

from scapy.fields import ByteEnumField, StrField, ConditionalField, \
    BitEnumField, BitField, XByteField, FieldListField, \
    XShortField, X3BytesField, XIntField, ByteField, \
    ShortField, ObservableDict, XShortEnumField, XByteEnumField
from scapy.packet import Packet, bind_layers, NoPayload, Raw
from scapy.config import conf
from scapy.error import log_loading, Scapy_Exception
from scapy.utils import PeriodicSenderThread, make_lined_table
from scapy.contrib.isotp import ISOTP
from scapy.modules import six
from scapy.error import warning


"""
UDS
"""

try:
    if conf.contribs['UDS']['treat-response-pending-as-answer']:
        pass
except KeyError:
    log_loading.info("Specify \"conf.contribs['UDS'] = "
                     "{'treat-response-pending-as-answer': True}\" to treat "
                     "a negative response 'requestCorrectlyReceived-"
                     "ResponsePending' as answer of a request. \n"
                     "The default value is False.")
    conf.contribs['UDS'] = {'treat-response-pending-as-answer': False}


class UDS(ISOTP):
    services = ObservableDict(
        {0x10: 'DiagnosticSessionControl',
         0x11: 'ECUReset',
         0x14: 'ClearDiagnosticInformation',
         0x19: 'ReadDTCInformation',
         0x22: 'ReadDataByIdentifier',
         0x23: 'ReadMemoryByAddress',
         0x24: 'ReadScalingDataByIdentifier',
         0x27: 'SecurityAccess',
         0x28: 'CommunicationControl',
         0x2A: 'ReadDataPeriodicIdentifier',
         0x2C: 'DynamicallyDefineDataIdentifier',
         0x2E: 'WriteDataByIdentifier',
         0x2F: 'InputOutputControlByIdentifier',
         0x31: 'RoutineControl',
         0x34: 'RequestDownload',
         0x35: 'RequestUpload',
         0x36: 'TransferData',
         0x37: 'RequestTransferExit',
         0x3D: 'WriteMemoryByAddress',
         0x3E: 'TesterPresent',
         0x50: 'DiagnosticSessionControlPositiveResponse',
         0x51: 'ECUResetPositiveResponse',
         0x54: 'ClearDiagnosticInformationPositiveResponse',
         0x59: 'ReadDTCInformationPositiveResponse',
         0x62: 'ReadDataByIdentifierPositiveResponse',
         0x63: 'ReadMemoryByAddressPositiveResponse',
         0x64: 'ReadScalingDataByIdentifierPositiveResponse',
         0x67: 'SecurityAccessPositiveResponse',
         0x68: 'CommunicationControlPositiveResponse',
         0x6A: 'ReadDataPeriodicIdentifierPositiveResponse',
         0x6C: 'DynamicallyDefineDataIdentifierPositiveResponse',
         0x6E: 'WriteDataByIdentifierPositiveResponse',
         0x6F: 'InputOutputControlByIdentifierPositiveResponse',
         0x71: 'RoutineControlPositiveResponse',
         0x74: 'RequestDownloadPositiveResponse',
         0x75: 'RequestUploadPositiveResponse',
         0x76: 'TransferDataPositiveResponse',
         0x77: 'RequestTransferExitPositiveResponse',
         0x7D: 'WriteMemoryByAddressPositiveResponse',
         0x7E: 'TesterPresentPositiveResponse',
         0x83: 'AccessTimingParameter',
         0x84: 'SecuredDataTransmission',
         0x85: 'ControlDTCSetting',
         0x86: 'ResponseOnEvent',
         0x87: 'LinkControl',
         0xC3: 'AccessTimingParameterPositiveResponse',
         0xC4: 'SecuredDataTransmissionPositiveResponse',
         0xC5: 'ControlDTCSettingPositiveResponse',
         0xC6: 'ResponseOnEventPositiveResponse',
         0xC7: 'LinkControlPositiveResponse',
         0x7f: 'NegativeResponse'})
    name = 'UDS'
    fields_desc = [
        XByteEnumField('service', 0, services)
    ]

    def answers(self, other):
        if other.__class__ != self.__class__:
            return False
        if self.service == 0x7f:
            return self.payload.answers(other)
        if self.service == (other.service + 0x40):
            if isinstance(self.payload, NoPayload) or \
                    isinstance(other.payload, NoPayload):
                return len(self) <= len(other)
            else:
                return self.payload.answers(other.payload)
        return False

    def hashret(self):
        if self.service == 0x7f:
            return struct.pack('B', self.requestServiceId)
        return struct.pack('B', self.service & ~0x40)


# ########################DSC###################################
class UDS_DSC(Packet):
    diagnosticSessionTypes = ObservableDict({
        0x00: 'ISOSAEReserved',
        0x01: 'defaultSession',
        0x02: 'programmingSession',
        0x03: 'extendedDiagnosticSession',
        0x04: 'safetySystemDiagnosticSession',
        0x7F: 'ISOSAEReserved'})
    name = 'DiagnosticSessionControl'
    fields_desc = [
        ByteEnumField('diagnosticSessionType', 0, diagnosticSessionTypes)
    ]

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), \
            pkt.sprintf("%UDS_DSC.diagnosticSessionType%")


bind_layers(UDS, UDS_DSC, service=0x10)


class UDS_DSCPR(Packet):
    name = 'DiagnosticSessionControlPositiveResponse'
    fields_desc = [
        ByteEnumField('diagnosticSessionType', 0,
                      UDS_DSC.diagnosticSessionTypes),
        StrField('sessionParameterRecord', B"")
    ]

    def answers(self, other):
        return other.__class__ == UDS_DSC and \
            other.diagnosticSessionType == self.diagnosticSessionType

    @staticmethod
    def modifies_ecu_state(pkt, ecu):
        ecu.current_session = pkt.diagnosticSessionType

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), \
            pkt.sprintf("%UDS_DSCPR.diagnosticSessionType%")


bind_layers(UDS, UDS_DSCPR, service=0x50)


# #########################ER###################################
class UDS_ER(Packet):
    resetTypes = {
        0x00: 'ISOSAEReserved',
        0x01: 'hardReset',
        0x02: 'keyOffOnReset',
        0x03: 'softReset',
        0x04: 'enableRapidPowerShutDown',
        0x05: 'disableRapidPowerShutDown',
        0x7F: 'ISOSAEReserved'}
    name = 'ECUReset'
    fields_desc = [
        ByteEnumField('resetType', 0, resetTypes)
    ]

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), \
            pkt.sprintf("%UDS_ER.resetType%")


bind_layers(UDS, UDS_ER, service=0x11)


class UDS_ERPR(Packet):
    name = 'ECUResetPositiveResponse'
    fields_desc = [
        ByteEnumField('resetType', 0, UDS_ER.resetTypes),
        ConditionalField(ByteField('powerDownTime', 0),
                         lambda pkt: pkt.resetType == 0x04)
    ]

    def answers(self, other):
        return other.__class__ == UDS_ER

    @staticmethod
    def modifies_ecu_state(_, ecu):
        ecu.reset()

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), \
            pkt.sprintf("%UDS_ER.resetType%")


bind_layers(UDS, UDS_ERPR, service=0x51)


# #########################SA###################################
class UDS_SA(Packet):
    name = 'SecurityAccess'
    fields_desc = [
        ByteField('securityAccessType', 0),
        ConditionalField(StrField('securityAccessDataRecord', B""),
                         lambda pkt: pkt.securityAccessType % 2 == 1),
        ConditionalField(StrField('securityKey', B""),
                         lambda pkt: pkt.securityAccessType % 2 == 0)
    ]

    @staticmethod
    def get_log(pkt):
        if pkt.securityAccessType % 2 == 1:
            return pkt.sprintf("%UDS.service%"),\
                (pkt.securityAccessType, None)
        else:
            return pkt.sprintf("%UDS.service%"),\
                (pkt.securityAccessType, pkt.securityKey)


bind_layers(UDS, UDS_SA, service=0x27)


class UDS_SAPR(Packet):
    name = 'SecurityAccessPositiveResponse'
    fields_desc = [
        ByteField('securityAccessType', 0),
        ConditionalField(StrField('securitySeed', B""),
                         lambda pkt: pkt.securityAccessType % 2 == 1),
    ]

    def answers(self, other):
        return other.__class__ == UDS_SA \
            and other.securityAccessType == self.securityAccessType

    @staticmethod
    def modifies_ecu_state(pkt, ecu):
        if pkt.securityAccessType % 2 == 0:
            ecu.current_security_level = pkt.securityAccessType

    @staticmethod
    def get_log(pkt):
        if pkt.securityAccessType % 2 == 0:
            return pkt.sprintf("%UDS.service%"),\
                (pkt.securityAccessType, None)
        else:
            return pkt.sprintf("%UDS.service%"),\
                (pkt.securityAccessType, pkt.securitySeed)


bind_layers(UDS, UDS_SAPR, service=0x67)


# #########################CC###################################
class UDS_CC(Packet):
    controlTypes = {
        0x00: 'enableRxAndTx',
        0x01: 'enableRxAndDisableTx',
        0x02: 'disableRxAndEnableTx',
        0x03: 'disableRxAndTx'
    }
    name = 'CommunicationControl'
    fields_desc = [
        ByteEnumField('controlType', 0, controlTypes),
        BitEnumField('communicationType0', 0, 2,
                     {0: 'ISOSAEReserved',
                      1: 'normalCommunicationMessages',
                      2: 'networkManagmentCommunicationMessages',
                      3: 'networkManagmentCommunicationMessages and '
                         'normalCommunicationMessages'}),
        BitField('communicationType1', 0, 2),
        BitEnumField('communicationType2', 0, 4,
                     {0: 'Disable/Enable specified communication Type',
                      1: 'Disable/Enable specific subnet',
                      2: 'Disable/Enable specific subnet',
                      3: 'Disable/Enable specific subnet',
                      4: 'Disable/Enable specific subnet',
                      5: 'Disable/Enable specific subnet',
                      6: 'Disable/Enable specific subnet',
                      7: 'Disable/Enable specific subnet',
                      8: 'Disable/Enable specific subnet',
                      9: 'Disable/Enable specific subnet',
                      10: 'Disable/Enable specific subnet',
                      11: 'Disable/Enable specific subnet',
                      12: 'Disable/Enable specific subnet',
                      13: 'Disable/Enable specific subnet',
                      14: 'Disable/Enable specific subnet',
                      15: 'Disable/Enable network'})
    ]

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), \
            pkt.sprintf("%UDS_CC.controlType%")


bind_layers(UDS, UDS_CC, service=0x28)


class UDS_CCPR(Packet):
    name = 'CommunicationControlPositiveResponse'
    fields_desc = [
        ByteEnumField('controlType', 0, UDS_CC.controlTypes)
    ]

    def answers(self, other):
        return other.__class__ == UDS_CC \
            and other.controlType == self.controlType

    @staticmethod
    def modifies_ecu_state(pkt, ecu):
        ecu.communication_control = pkt.controlType

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), \
            pkt.sprintf("%UDS_CCPR.controlType%")


bind_layers(UDS, UDS_CCPR, service=0x68)


# #########################TP###################################
class UDS_TP(Packet):
    name = 'TesterPresent'
    fields_desc = [
        ByteField('subFunction', 0)
    ]

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), pkt.subFunction


bind_layers(UDS, UDS_TP, service=0x3E)


class UDS_TPPR(Packet):
    name = 'TesterPresentPositiveResponse'
    fields_desc = [
        ByteField('zeroSubFunction', 0)
    ]

    def answers(self, other):
        return other.__class__ == UDS_TP

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), pkt.zeroSubFunction


bind_layers(UDS, UDS_TPPR, service=0x7E)


# #########################ATP###################################
class UDS_ATP(Packet):
    timingParameterAccessTypes = {
        0: 'ISOSAEReserved',
        1: 'readExtendedTimingParameterSet',
        2: 'setTimingParametersToDefaultValues',
        3: 'readCurrentlyActiveTimingParameters',
        4: 'setTimingParametersToGivenValues'
    }
    name = 'AccessTimingParameter'
    fields_desc = [
        ByteEnumField('timingParameterAccessType', 0,
                      timingParameterAccessTypes),
        ConditionalField(StrField('timingParameterRequestRecord', B""),
                         lambda pkt: pkt.timingParameterAccessType == 0x4)
    ]


bind_layers(UDS, UDS_ATP, service=0x83)


class UDS_ATPPR(Packet):
    name = 'AccessTimingParameterPositiveResponse'
    fields_desc = [
        ByteEnumField('timingParameterAccessType', 0,
                      UDS_ATP.timingParameterAccessTypes),
        ConditionalField(StrField('timingParameterResponseRecord', B""),
                         lambda pkt: pkt.timingParameterAccessType == 0x3)
    ]

    def answers(self, other):
        return other.__class__ == UDS_ATP \
            and other.timingParameterAccessType == \
            self.timingParameterAccessType


bind_layers(UDS, UDS_ATPPR, service=0xC3)


# #########################SDT###################################
class UDS_SDT(Packet):
    name = 'SecuredDataTransmission'
    fields_desc = [
        StrField('securityDataRequestRecord', B"")
    ]

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), pkt.securityDataRequestRecord


bind_layers(UDS, UDS_SDT, service=0x84)


class UDS_SDTPR(Packet):
    name = 'SecuredDataTransmissionPositiveResponse'
    fields_desc = [
        StrField('securityDataResponseRecord', B"")
    ]

    def answers(self, other):
        return other.__class__ == UDS_SDT

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), pkt.securityDataResponseRecord


bind_layers(UDS, UDS_SDTPR, service=0xC4)


# #########################CDTCS###################################
class UDS_CDTCS(Packet):
    DTCSettingTypes = {
        0: 'ISOSAEReserved',
        1: 'on',
        2: 'off'
    }
    name = 'ControlDTCSetting'
    fields_desc = [
        ByteEnumField('DTCSettingType', 0, DTCSettingTypes),
        StrField('DTCSettingControlOptionRecord', B"")
    ]

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), \
            pkt.sprintf("%UDS_CDTCS.DTCSettingType%")


bind_layers(UDS, UDS_CDTCS, service=0x85)


class UDS_CDTCSPR(Packet):
    name = 'ControlDTCSettingPositiveResponse'
    fields_desc = [
        ByteEnumField('DTCSettingType', 0, UDS_CDTCS.DTCSettingTypes)
    ]

    def answers(self, other):
        return other.__class__ == UDS_CDTCS

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), \
            pkt.sprintf("%UDS_CDTCSPR.DTCSettingType%")


bind_layers(UDS, UDS_CDTCSPR, service=0xC5)


# #########################ROE###################################
# TODO: improve this protocol implementation
class UDS_ROE(Packet):
    eventTypes = {
        0: 'doNotStoreEvent',
        1: 'storeEvent'
    }
    name = 'ResponseOnEvent'
    fields_desc = [
        ByteEnumField('eventType', 0, eventTypes),
        ByteField('eventWindowTime', 0),
        StrField('eventTypeRecord', B"")
    ]


bind_layers(UDS, UDS_ROE, service=0x86)


class UDS_ROEPR(Packet):
    name = 'ResponseOnEventPositiveResponse'
    fields_desc = [
        ByteEnumField('eventType', 0, UDS_ROE.eventTypes),
        ByteField('numberOfIdentifiedEvents', 0),
        ByteField('eventWindowTime', 0),
        StrField('eventTypeRecord', B"")
    ]

    def answers(self, other):
        return other.__class__ == UDS_ROE \
            and other.eventType == self.eventType


bind_layers(UDS, UDS_ROEPR, service=0xC6)


# #########################LC###################################
class UDS_LC(Packet):
    linkControlTypes = {
        0: 'ISOSAEReserved',
        1: 'verifyBaudrateTransitionWithFixedBaudrate',
        2: 'verifyBaudrateTransitionWithSpecificBaudrate',
        3: 'transitionBaudrate'
    }
    name = 'LinkControl'
    fields_desc = [
        ByteEnumField('linkControlType', 0, linkControlTypes),
        ConditionalField(ByteField('baudrateIdentifier', 0),
                         lambda pkt: pkt.linkControlType == 0x1),
        ConditionalField(ByteField('baudrateHighByte', 0),
                         lambda pkt: pkt.linkControlType == 0x2),
        ConditionalField(ByteField('baudrateMiddleByte', 0),
                         lambda pkt: pkt.linkControlType == 0x2),
        ConditionalField(ByteField('baudrateLowByte', 0),
                         lambda pkt: pkt.linkControlType == 0x2)
    ]

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), \
            pkt.sprintf("%UDS.linkControlType%")


bind_layers(UDS, UDS_LC, service=0x87)


class UDS_LCPR(Packet):
    name = 'LinkControlPositiveResponse'
    fields_desc = [
        ByteEnumField('linkControlType', 0, UDS_LC.linkControlTypes)
    ]

    def answers(self, other):
        return other.__class__ == UDS_LC \
            and other.linkControlType == self.linkControlType

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), \
            pkt.sprintf("%UDS.linkControlType%")


bind_layers(UDS, UDS_LCPR, service=0xC7)


# #########################RDBI###################################
class UDS_RDBI(Packet):
    dataIdentifiers = ObservableDict()
    name = 'ReadDataByIdentifier'
    fields_desc = [
        FieldListField("identifiers", [0],
                       XShortEnumField('dataIdentifier', 0,
                                       dataIdentifiers))
    ]

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), \
            pkt.sprintf("%UDS_RDBI.identifiers%")


bind_layers(UDS, UDS_RDBI, service=0x22)


class UDS_RDBIPR(Packet):
    name = 'ReadDataByIdentifierPositiveResponse'
    fields_desc = [
        XShortEnumField('dataIdentifier', 0,
                        UDS_RDBI.dataIdentifiers),
    ]

    def answers(self, other):
        return other.__class__ == UDS_RDBI \
            and self.dataIdentifier in other.identifiers

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), \
            pkt.sprintf("%UDS_RDBIPR.dataIdentifier%")


bind_layers(UDS, UDS_RDBIPR, service=0x62)


# #########################RMBA###################################
class UDS_RMBA(Packet):
    name = 'ReadMemoryByAddress'
    fields_desc = [
        BitField('memorySizeLen', 0, 4),
        BitField('memoryAddressLen', 0, 4),
        ConditionalField(XByteField('memoryAddress1', 0),
                         lambda pkt: pkt.memoryAddressLen == 1),
        ConditionalField(XShortField('memoryAddress2', 0),
                         lambda pkt: pkt.memoryAddressLen == 2),
        ConditionalField(X3BytesField('memoryAddress3', 0),
                         lambda pkt: pkt.memoryAddressLen == 3),
        ConditionalField(XIntField('memoryAddress4', 0),
                         lambda pkt: pkt.memoryAddressLen == 4),
        ConditionalField(XByteField('memorySize1', 0),
                         lambda pkt: pkt.memorySizeLen == 1),
        ConditionalField(XShortField('memorySize2', 0),
                         lambda pkt: pkt.memorySizeLen == 2),
        ConditionalField(X3BytesField('memorySize3', 0),
                         lambda pkt: pkt.memorySizeLen == 3),
        ConditionalField(XIntField('memorySize4', 0),
                         lambda pkt: pkt.memorySizeLen == 4),
    ]

    @staticmethod
    def get_log(pkt):
        addr = getattr(pkt, "memoryAddress%d" % pkt.memoryAddressLen)
        size = getattr(pkt, "memorySize%d" % pkt.memorySizeLen)
        return pkt.sprintf("%UDS.service%"), (addr, size)


bind_layers(UDS, UDS_RMBA, service=0x23)


class UDS_RMBAPR(Packet):
    name = 'ReadMemoryByAddressPositiveResponse'
    fields_desc = [
        StrField('dataRecord', None, fmt="B")
    ]

    def answers(self, other):
        return other.__class__ == UDS_RMBA

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), pkt.dataRecord


bind_layers(UDS, UDS_RMBAPR, service=0x63)


# #########################RSDBI###################################
class UDS_RSDBI(Packet):
    name = 'ReadScalingDataByIdentifier'
    dataIdentifiers = ObservableDict()
    fields_desc = [
        XShortEnumField('dataIdentifier', 0, dataIdentifiers)
    ]


bind_layers(UDS, UDS_RSDBI, service=0x24)


# TODO: Implement correct scaling here, instead of using just the dataRecord
class UDS_RSDBIPR(Packet):
    name = 'ReadScalingDataByIdentifierPositiveResponse'
    fields_desc = [
        XShortEnumField('dataIdentifier', 0, UDS_RSDBI.dataIdentifiers),
        ByteField('scalingByte', 0),
        StrField('dataRecord', None, fmt="B")
    ]

    def answers(self, other):
        return other.__class__ == UDS_RSDBI \
            and other.dataIdentifier == self.dataIdentifier


bind_layers(UDS, UDS_RSDBIPR, service=0x64)


# #########################RDBPI###################################
class UDS_RDBPI(Packet):
    transmissionModes = {
        0: 'ISOSAEReserved',
        1: 'sendAtSlowRate',
        2: 'sendAtMediumRate',
        3: 'sendAtFastRate',
        4: 'stopSending'
    }
    name = 'ReadDataByPeriodicIdentifier'
    fields_desc = [
        ByteEnumField('transmissionMode', 0, transmissionModes),
        ByteField('periodicDataIdentifier', 0),
        StrField('furtherPeriodicDataIdentifier', 0, fmt="B")
    ]


bind_layers(UDS, UDS_RDBPI, service=0x2A)


# TODO: Implement correct scaling here, instead of using just the dataRecord
class UDS_RDBPIPR(Packet):
    name = 'ReadDataByPeriodicIdentifierPositiveResponse'
    fields_desc = [
        ByteField('periodicDataIdentifier', 0),
        StrField('dataRecord', None, fmt="B")
    ]

    def answers(self, other):
        return other.__class__ == UDS_RDBPI \
            and other.periodicDataIdentifier == self.periodicDataIdentifier


bind_layers(UDS, UDS_RDBPIPR, service=0x6A)


# #########################DDDI###################################
# TODO: Implement correct interpretation here,
# instead of using just the dataRecord
class UDS_DDDI(Packet):
    name = 'DynamicallyDefineDataIdentifier'
    subFunctions = {0x1: "defineByIdentifier",
                    0x2: "defineByMemoryAddress",
                    0x3: "clearDynamicallyDefinedDataIdentifier"}
    fields_desc = [
        ByteEnumField('subFunction', 0, subFunctions),
        StrField('dataRecord', 0, fmt="B")
    ]


bind_layers(UDS, UDS_DDDI, service=0x2C)


class UDS_DDDIPR(Packet):
    name = 'DynamicallyDefineDataIdentifierPositiveResponse'
    fields_desc = [
        ByteEnumField('subFunction', 0, UDS_DDDI.subFunctions),
        XShortField('dynamicallyDefinedDataIdentifier', 0)
    ]

    def answers(self, other):
        return other.__class__ == UDS_DDDI \
            and other.subFunction == self.subFunction


bind_layers(UDS, UDS_DDDIPR, service=0x6C)


# #########################WDBI###################################
class UDS_WDBI(Packet):
    name = 'WriteDataByIdentifier'
    fields_desc = [
        XShortEnumField('dataIdentifier', 0,
                        UDS_RDBI.dataIdentifiers)
    ]

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), \
            pkt.sprintf("%UDS_WDBI.dataIdentifier%")


bind_layers(UDS, UDS_WDBI, service=0x2E)


class UDS_WDBIPR(Packet):
    name = 'WriteDataByIdentifierPositiveResponse'
    fields_desc = [
        XShortEnumField('dataIdentifier', 0,
                        UDS_RDBI.dataIdentifiers),
    ]

    def answers(self, other):
        return other.__class__ == UDS_WDBI \
            and other.dataIdentifier == self.dataIdentifier

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), \
            pkt.sprintf("%UDS_WDBIPR.dataIdentifier%")


bind_layers(UDS, UDS_WDBIPR, service=0x6E)


# #########################WMBA###################################
class UDS_WMBA(Packet):
    name = 'WriteMemoryByAddress'
    fields_desc = [
        BitField('memorySizeLen', 0, 4),
        BitField('memoryAddressLen', 0, 4),
        ConditionalField(XByteField('memoryAddress1', 0),
                         lambda pkt: pkt.memoryAddressLen == 1),
        ConditionalField(XShortField('memoryAddress2', 0),
                         lambda pkt: pkt.memoryAddressLen == 2),
        ConditionalField(X3BytesField('memoryAddress3', 0),
                         lambda pkt: pkt.memoryAddressLen == 3),
        ConditionalField(XIntField('memoryAddress4', 0),
                         lambda pkt: pkt.memoryAddressLen == 4),
        ConditionalField(XByteField('memorySize1', 0),
                         lambda pkt: pkt.memorySizeLen == 1),
        ConditionalField(XShortField('memorySize2', 0),
                         lambda pkt: pkt.memorySizeLen == 2),
        ConditionalField(X3BytesField('memorySize3', 0),
                         lambda pkt: pkt.memorySizeLen == 3),
        ConditionalField(XIntField('memorySize4', 0),
                         lambda pkt: pkt.memorySizeLen == 4),
        StrField('dataRecord', b'\x00', fmt="B"),

    ]

    @staticmethod
    def get_log(pkt):
        addr = getattr(pkt, "memoryAddress%d" % pkt.memoryAddressLen)
        size = getattr(pkt, "memorySize%d" % pkt.memorySizeLen)
        return pkt.sprintf("%UDS.service%"), (addr, size, pkt.dataRecord)


bind_layers(UDS, UDS_WMBA, service=0x3D)


class UDS_WMBAPR(Packet):
    name = 'WriteMemoryByAddressPositiveResponse'
    fields_desc = [
        BitField('memorySizeLen', 0, 4),
        BitField('memoryAddressLen', 0, 4),
        ConditionalField(XByteField('memoryAddress1', 0),
                         lambda pkt: pkt.memoryAddressLen == 1),
        ConditionalField(XShortField('memoryAddress2', 0),
                         lambda pkt: pkt.memoryAddressLen == 2),
        ConditionalField(X3BytesField('memoryAddress3', 0),
                         lambda pkt: pkt.memoryAddressLen == 3),
        ConditionalField(XIntField('memoryAddress4', 0),
                         lambda pkt: pkt.memoryAddressLen == 4),
        ConditionalField(XByteField('memorySize1', 0),
                         lambda pkt: pkt.memorySizeLen == 1),
        ConditionalField(XShortField('memorySize2', 0),
                         lambda pkt: pkt.memorySizeLen == 2),
        ConditionalField(X3BytesField('memorySize3', 0),
                         lambda pkt: pkt.memorySizeLen == 3),
        ConditionalField(XIntField('memorySize4', 0),
                         lambda pkt: pkt.memorySizeLen == 4)
    ]

    def answers(self, other):
        return other.__class__ == UDS_WMBA \
            and other.memorySizeLen == self.memorySizeLen \
            and other.memoryAddressLen == self.memoryAddressLen

    @staticmethod
    def get_log(pkt):
        addr = getattr(pkt, "memoryAddress%d" % pkt.memoryAddressLen)
        size = getattr(pkt, "memorySize%d" % pkt.memorySizeLen)
        return pkt.sprintf("%UDS.service%"), (addr, size)


bind_layers(UDS, UDS_WMBAPR, service=0x7D)


# #########################CDTCI###################################
class UDS_CDTCI(Packet):
    name = 'ClearDiagnosticInformation'
    fields_desc = [
        ByteField('groupOfDTCHighByte', 0),
        ByteField('groupOfDTCMiddleByte', 0),
        ByteField('groupOfDTCLowByte', 0),
    ]

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), (pkt.groupOfDTCHighByte,
                                              pkt.groupOfDTCMiddleByte,
                                              pkt.groupOfDTCLowByte)


bind_layers(UDS, UDS_CDTCI, service=0x14)


class UDS_CDTCIPR(Packet):
    name = 'ClearDiagnosticInformationPositiveResponse'

    def answers(self, other):
        return other.__class__ == UDS_CDTCI

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), None


bind_layers(UDS, UDS_CDTCIPR, service=0x54)


# #########################RDTCI###################################
class UDS_RDTCI(Packet):
    reportTypes = {
        0: 'ISOSAEReserved',
        1: 'reportNumberOfDTCByStatusMask',
        2: 'reportDTCByStatusMask',
        3: 'reportDTCSnapshotIdentification',
        4: 'reportDTCSnapshotRecordByDTCNumber',
        5: 'reportDTCSnapshotRecordByRecordNumber',
        6: 'reportDTCExtendedDataRecordByDTCNumber',
        7: 'reportNumberOfDTCBySeverityMaskRecord',
        8: 'reportDTCBySeverityMaskRecord',
        9: 'reportSeverityInformationOfDTC',
        10: 'reportSupportedDTC',
        11: 'reportFirstTestFailedDTC',
        12: 'reportFirstConfirmedDTC',
        13: 'reportMostRecentTestFailedDTC',
        14: 'reportMostRecentConfirmedDTC',
        15: 'reportMirrorMemoryDTCByStatusMask',
        16: 'reportMirrorMemoryDTCExtendedDataRecordByDTCNumber',
        17: 'reportNumberOfMirrorMemoryDTCByStatusMask',
        18: 'reportNumberOfEmissionsRelatedOBDDTCByStatusMask',
        19: 'reportEmissionsRelatedOBDDTCByStatusMask',
        20: 'reportDTCFaultDetectionCounter',
        21: 'reportDTCWithPermanentStatus'
    }
    name = 'ReadDTCInformation'
    fields_desc = [
        ByteEnumField('reportType', 0, reportTypes),
        ConditionalField(XByteField('DTCStatusMask', 0),
                         lambda pkt: pkt.reportType in [0x01, 0x02, 0x0f,
                                                        0x11, 0x12, 0x13]),
        ConditionalField(ByteField('DTCHighByte', 0),
                         lambda pkt: pkt.reportType in [0x3, 0x4, 0x6,
                                                        0x10, 0x09]),
        ConditionalField(ByteField('DTCMiddleByte', 0),
                         lambda pkt: pkt.reportType in [0x3, 0x4, 0x6,
                                                        0x10, 0x09]),
        ConditionalField(ByteField('DTCLowByte', 0),
                         lambda pkt: pkt.reportType in [0x3, 0x4, 0x6,
                                                        0x10, 0x09]),
        ConditionalField(ByteField('DTCSnapshotRecordNumber', 0),
                         lambda pkt: pkt.reportType in [0x3, 0x4, 0x5]),
        ConditionalField(ByteField('DTCExtendedDataRecordNumber', 0),
                         lambda pkt: pkt.reportType in [0x6, 0x10]),
        ConditionalField(ByteField('DTCSeverityMask', 0),
                         lambda pkt: pkt.reportType in [0x07, 0x08]),
        ConditionalField(ByteField('DTCStatusMask', 0),
                         lambda pkt: pkt.reportType in [0x07, 0x08]),
    ]

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), repr(pkt)


bind_layers(UDS, UDS_RDTCI, service=0x19)


class UDS_RDTCIPR(Packet):
    name = 'ReadDTCInformationPositiveResponse'
    fields_desc = [
        ByteEnumField('reportType', 0, UDS_RDTCI.reportTypes),
        ConditionalField(XByteField('DTCStatusAvailabilityMask', 0),
                         lambda pkt: pkt.reportType in [0x01, 0x07, 0x11,
                                                        0x12, 0x02, 0x0A,
                                                        0x0B, 0x0C, 0x0D,
                                                        0x0E, 0x0F, 0x13,
                                                        0x15]),
        ConditionalField(ByteEnumField('DTCFormatIdentifier', 0,
                                       {0: 'ISO15031-6DTCFormat',
                                        1: 'UDS-1DTCFormat',
                                        2: 'SAEJ1939-73DTCFormat',
                                        3: 'ISO11992-4DTCFormat'}),
                         lambda pkt: pkt.reportType in [0x01, 0x07,
                                                        0x11, 0x12]),
        ConditionalField(ShortField('DTCCount', 0),
                         lambda pkt: pkt.reportType in [0x01, 0x07,
                                                        0x11, 0x12]),
        ConditionalField(StrField('DTCAndStatusRecord', 0),
                         lambda pkt: pkt.reportType in [0x02, 0x0A, 0x0B,
                                                        0x0C, 0x0D, 0x0E,
                                                        0x0F, 0x13, 0x15]),
        ConditionalField(StrField('dataRecord', 0),
                         lambda pkt: pkt.reportType in [0x03, 0x04, 0x05,
                                                        0x06, 0x08, 0x09,
                                                        0x10, 0x14])
    ]

    def answers(self, other):
        return other.__class__ == UDS_RDTCI \
            and other.reportType == self.reportType

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), repr(pkt)


bind_layers(UDS, UDS_RDTCIPR, service=0x59)


# #########################RC###################################
class UDS_RC(Packet):
    routineControlTypes = {
        0: 'ISOSAEReserved',
        1: 'startRoutine',
        2: 'stopRoutine',
        3: 'requestRoutineResults'
    }
    routineControlIdentifiers = ObservableDict()
    name = 'RoutineControl'
    fields_desc = [
        ByteEnumField('routineControlType', 0, routineControlTypes),
        XShortEnumField('routineIdentifier', 0, routineControlIdentifiers),
        StrField('routineControlOptionRecord', 0, fmt="B"),
    ]

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"),\
            (pkt.routineControlType,
             pkt.routineIdentifier,
             pkt.routineControlOptionRecord)


bind_layers(UDS, UDS_RC, service=0x31)


class UDS_RCPR(Packet):
    name = 'RoutineControlPositiveResponse'
    fields_desc = [
        ByteEnumField('routineControlType', 0,
                      UDS_RC.routineControlTypes),
        XShortEnumField('routineIdentifier', 0,
                        UDS_RC.routineControlIdentifiers),
        StrField('routineStatusRecord', 0, fmt="B"),
    ]

    def answers(self, other):
        return other.__class__ == UDS_RC \
            and other.routineControlType == self.routineControlType

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"),\
            (pkt.routineControlType,
             pkt.routineIdentifier,
             pkt.routineStatusRecord)


bind_layers(UDS, UDS_RCPR, service=0x71)


# #########################RD###################################
class UDS_RD(Packet):
    dataFormatIdentifiers = ObservableDict({
        0: 'noCompressionNoEncryption'
    })
    name = 'RequestDownload'
    fields_desc = [
        ByteEnumField('dataFormatIdentifier', 0, dataFormatIdentifiers),
        BitField('memorySizeLen', 0, 4),
        BitField('memoryAddressLen', 0, 4),
        ConditionalField(XByteField('memoryAddress1', 0),
                         lambda pkt: pkt.memoryAddressLen == 1),
        ConditionalField(XShortField('memoryAddress2', 0),
                         lambda pkt: pkt.memoryAddressLen == 2),
        ConditionalField(X3BytesField('memoryAddress3', 0),
                         lambda pkt: pkt.memoryAddressLen == 3),
        ConditionalField(XIntField('memoryAddress4', 0),
                         lambda pkt: pkt.memoryAddressLen == 4),
        ConditionalField(XByteField('memorySize1', 0),
                         lambda pkt: pkt.memorySizeLen == 1),
        ConditionalField(XShortField('memorySize2', 0),
                         lambda pkt: pkt.memorySizeLen == 2),
        ConditionalField(X3BytesField('memorySize3', 0),
                         lambda pkt: pkt.memorySizeLen == 3),
        ConditionalField(XIntField('memorySize4', 0),
                         lambda pkt: pkt.memorySizeLen == 4)
    ]

    @staticmethod
    def get_log(pkt):
        addr = getattr(pkt, "memoryAddress%d" % pkt.memoryAddressLen)
        size = getattr(pkt, "memorySize%d" % pkt.memorySizeLen)
        return pkt.sprintf("%UDS.service%"), (addr, size)


bind_layers(UDS, UDS_RD, service=0x34)


class UDS_RDPR(Packet):
    name = 'RequestDownloadPositiveResponse'
    fields_desc = [
        BitField('memorySizeLen', 0, 4),
        BitField('reserved', 0, 4),
        StrField('maxNumberOfBlockLength', 0, fmt="B"),
    ]

    def answers(self, other):
        return other.__class__ == UDS_RD

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), pkt.memorySizeLen


bind_layers(UDS, UDS_RDPR, service=0x74)


# #########################RU###################################
class UDS_RU(Packet):
    name = 'RequestUpload'
    fields_desc = [
        ByteEnumField('dataFormatIdentifier', 0,
                      UDS_RD.dataFormatIdentifiers),
        BitField('memorySizeLen', 0, 4),
        BitField('memoryAddressLen', 0, 4),
        ConditionalField(XByteField('memoryAddress1', 0),
                         lambda pkt: pkt.memoryAddressLen == 1),
        ConditionalField(XShortField('memoryAddress2', 0),
                         lambda pkt: pkt.memoryAddressLen == 2),
        ConditionalField(X3BytesField('memoryAddress3', 0),
                         lambda pkt: pkt.memoryAddressLen == 3),
        ConditionalField(XIntField('memoryAddress4', 0),
                         lambda pkt: pkt.memoryAddressLen == 4),
        ConditionalField(XByteField('memorySize1', 0),
                         lambda pkt: pkt.memorySizeLen == 1),
        ConditionalField(XShortField('memorySize2', 0),
                         lambda pkt: pkt.memorySizeLen == 2),
        ConditionalField(X3BytesField('memorySize3', 0),
                         lambda pkt: pkt.memorySizeLen == 3),
        ConditionalField(XIntField('memorySize4', 0),
                         lambda pkt: pkt.memorySizeLen == 4)
    ]

    @staticmethod
    def get_log(pkt):
        addr = getattr(pkt, "memoryAddress%d" % pkt.memoryAddressLen)
        size = getattr(pkt, "memorySize%d" % pkt.memorySizeLen)
        return pkt.sprintf("%UDS.service%"), (addr, size)


bind_layers(UDS, UDS_RU, service=0x35)


class UDS_RUPR(Packet):
    name = 'RequestUploadPositiveResponse'
    fields_desc = [
        BitField('memorySizeLen', 0, 4),
        BitField('reserved', 0, 4),
        StrField('maxNumberOfBlockLength', 0, fmt="B"),
    ]

    def answers(self, other):
        return other.__class__ == UDS_RU

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), pkt.memorySizeLen


bind_layers(UDS, UDS_RUPR, service=0x75)


# #########################TD###################################
class UDS_TD(Packet):
    name = 'TransferData'
    fields_desc = [
        ByteField('blockSequenceCounter', 0),
        StrField('transferRequestParameterRecord', 0, fmt="B")
    ]

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"),\
            (pkt.blockSequenceCounter, pkt.transferRequestParameterRecord)


bind_layers(UDS, UDS_TD, service=0x36)


class UDS_TDPR(Packet):
    name = 'TransferDataPositiveResponse'
    fields_desc = [
        ByteField('blockSequenceCounter', 0),
        StrField('transferResponseParameterRecord', 0, fmt="B")
    ]

    def answers(self, other):
        return other.__class__ == UDS_TD \
            and other.blockSequenceCounter == self.blockSequenceCounter

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), pkt.blockSequenceCounter


bind_layers(UDS, UDS_TDPR, service=0x76)


# #########################RTE###################################
class UDS_RTE(Packet):
    name = 'RequestTransferExit'
    fields_desc = [
        StrField('transferRequestParameterRecord', 0, fmt="B")
    ]

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"),\
            pkt.transferRequestParameterRecord


bind_layers(UDS, UDS_RTE, service=0x37)


class UDS_RTEPR(Packet):
    name = 'RequestTransferExitPositiveResponse'
    fields_desc = [
        StrField('transferResponseParameterRecord', 0, fmt="B")
    ]

    def answers(self, other):
        return other.__class__ == UDS_RTE

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"),\
            pkt.transferResponseParameterRecord


bind_layers(UDS, UDS_RTEPR, service=0x77)


# #########################IOCBI###################################
class UDS_IOCBI(Packet):
    name = 'InputOutputControlByIdentifier'
    dataIdentifiers = ObservableDict()
    fields_desc = [
        XShortEnumField('dataIdentifier', 0, dataIdentifiers),
        ByteField('controlOptionRecord', 0),
        StrField('controlEnableMaskRecord', 0, fmt="B")
    ]

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), pkt.dataIdentifier


bind_layers(UDS, UDS_IOCBI, service=0x2F)


class UDS_IOCBIPR(Packet):
    name = 'InputOutputControlByIdentifierPositiveResponse'
    fields_desc = [
        XShortField('dataIdentifier', 0),
        StrField('controlStatusRecord', 0, fmt="B")
    ]

    def answers(self, other):
        return other.__class__ == UDS_IOCBI \
            and other.dataIdentifier == self.dataIdentifier

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), pkt.dataIdentifier


bind_layers(UDS, UDS_IOCBIPR, service=0x6F)


# #########################NR###################################
class UDS_NR(Packet):
    negativeResponseCodes = {
        0x00: 'positiveResponse',
        0x10: 'generalReject',
        0x11: 'serviceNotSupported',
        0x12: 'subFunctionNotSupported',
        0x13: 'incorrectMessageLengthOrInvalidFormat',
        0x14: 'responseTooLong',
        0x20: 'ISOSAEReserved',
        0x21: 'busyRepeatRequest',
        0x22: 'conditionsNotCorrect',
        0x23: 'ISOSAEReserved',
        0x24: 'requestSequenceError',
        0x25: 'noResponseFromSubnetComponent',
        0x26: 'failurePreventsExecutionOfRequestedAction',
        0x31: 'requestOutOfRange',
        0x33: 'securityAccessDenied',
        0x35: 'invalidKey',
        0x36: 'exceedNumberOfAttempts',
        0x37: 'requiredTimeDelayNotExpired',
        0x70: 'uploadDownloadNotAccepted',
        0x71: 'transferDataSuspended',
        0x72: 'generalProgrammingFailure',
        0x73: 'wrongBlockSequenceCounter',
        0x78: 'requestCorrectlyReceived-ResponsePending',
        0x7E: 'subFunctionNotSupportedInActiveSession',
        0x7F: 'serviceNotSupportedInActiveSession',
        0x80: 'ISOSAEReserved',
        0x81: 'rpmTooHigh',
        0x82: 'rpmTooLow',
        0x83: 'engineIsRunning',
        0x84: 'engineIsNotRunning',
        0x85: 'engineRunTimeTooLow',
        0x86: 'temperatureTooHigh',
        0x87: 'temperatureTooLow',
        0x88: 'vehicleSpeedTooHigh',
        0x89: 'vehicleSpeedTooLow',
        0x8a: 'throttle/PedalTooHigh',
        0x8b: 'throttle/PedalTooLow',
        0x8c: 'transmissionRangeNotInNeutral',
        0x8d: 'transmissionRangeNotInGear',
        0x8e: 'ISOSAEReserved',
        0x8f: 'brakeSwitch(es)NotClosed',
        0x90: 'shifterLeverNotInPark',
        0x91: 'torqueConverterClutchLocked',
        0x92: 'voltageTooHigh',
        0x93: 'voltageTooLow',
    }
    name = 'NegativeResponse'
    fields_desc = [
        XByteEnumField('requestServiceId', 0, UDS.services),
        ByteEnumField('negativeResponseCode', 0, negativeResponseCodes)
    ]

    def answers(self, other):
        return self.requestServiceId == other.service and \
            (self.negativeResponseCode != 0x78 or
             conf.contribs['UDS']['treat-response-pending-as-answer'])

    @staticmethod
    def get_log(pkt):
        return pkt.sprintf("%UDS.service%"), \
            (pkt.sprintf("%UDS_NR.requestServiceId%"),
             pkt.sprintf("%UDS_NR.negativeResponseCode%"))


bind_layers(UDS, UDS_NR, service=0x7f)


# ##################################################################
# ######################## UTILS ###################################
# ##################################################################


class UDS_TesterPresentSender(PeriodicSenderThread):
    def __init__(self, sock, pkt=UDS() / UDS_TP(), interval=2):
        """ Thread to send TesterPresent messages packets periodically

        Args:
            sock: socket where packet is sent periodically
            pkt: packet to send
            interval: interval between two packets
        """
        PeriodicSenderThread.__init__(self, sock, pkt, interval)


class Graph:
    def __init__(self):
        """
        self.edges is a dict of all possible next nodes
        e.g. {'X': ['A', 'B', 'C', 'E'], ...}
        self.weights has all the weights between two nodes,
        with the two nodes as a tuple as the key
        e.g. {('X', 'A'): 7, ('X', 'B'): 2, ...}
        """
        self.edges = defaultdict(list)
        self.weights = {}

    def add_edge(self, from_node, to_node, weight=1):
        # Note: assumes edges are bi-directional
        self.edges[from_node].append(to_node)
        self.edges[to_node].append(from_node)
        self.weights[(from_node, to_node)] = weight
        self.weights[(to_node, from_node)] = weight

    @staticmethod
    def dijsktra(graph, initial, end):
        # shortest paths is a dict of nodes
        # whose value is a tuple of (previous node, weight)
        shortest_paths = {initial: (None, 0)}
        current_node = initial
        visited = set()

        while current_node != end:
            visited.add(current_node)
            destinations = graph.edges[current_node]
            weight_to_current_node = shortest_paths[current_node][1]

            for next_node in destinations:
                weight = \
                    graph.weights[(current_node, next_node)] + \
                    weight_to_current_node
                if next_node not in shortest_paths:
                    shortest_paths[next_node] = (current_node, weight)
                else:
                    current_shortest_weight = shortest_paths[next_node][1]
                    if current_shortest_weight > weight:
                        shortest_paths[next_node] = (current_node, weight)

            next_destinations = {node: shortest_paths[node] for node in
                                 shortest_paths if node not in visited}
            if not next_destinations:
                return None
            # next node is the destination with the lowest weight
            current_node = min(next_destinations,
                               key=lambda k: next_destinations[k][1])

        # Work back through destinations in shortest path
        path = []
        while current_node is not None:
            path.append(current_node)
            next_node = shortest_paths[current_node][0]
            current_node = next_node
        # Reverse path
        path = path[::-1]
        return path


class UDS_Enumerator(object):
    """ Base class for Enumerators

    Args:
        sock: socket where enumeration takes place
    """
    description = "About my results"
    negative_response_blacklist = []
    ScanResult = namedtuple("ScanResult", "session req resp")

    def __init__(self, sock):
        self.sock = sock
        self.results = list()

    def scan(self, session, requests, **kwargs):
        _tm = kwargs.pop("timeout", 0.5)
        _verb = kwargs.pop("verbose", False)
        _exit_if_service_not_supported = \
            kwargs.pop("exit_if_service_not_supported", True)
        for req in requests:
            res = self.sock.sr1(req, timeout=_tm, verbose=_verb, **kwargs)
            if res and res.service is 0x11 and _exit_if_service_not_supported:
                print("Exit scan because negative response "
                      "serviceNotSupported received!")
                return
            self.results.append(UDS_Enumerator.ScanResult(session, req, res))

    @property
    def filtered_results(self):
        return [r for r in self.results
                if r.resp is not None and
                (r.resp.service != 0x7f or r.resp.negativeResponseCode
                 not in self.negative_response_blacklist)]

    def show(self, filtered=True):
        data = self.results if not filtered else self.filtered_results
        print("\r\n\r\n" + "=" * (len(self.description) + 10))
        print(" " * 5 + self.description)
        print("-" * (len(self.description) + 10))
        print("%d requests were sent, %d answered, %d unanswered" %
              (len(self.results),
               len([r for r in self.results if r.resp is not None]),
               len([r for r in self.results if r.resp is None])))
        nrs = [r.resp for r in self.results if r.resp is not None and
               r.resp.service == 0x7f]
        print("%d negative responses were received" % len(nrs))
        nrcs = set([nr.negativeResponseCode for nr in nrs])
        print("These negative response codes were received %s" % nrcs)
        for nrc in nrcs:
            print("\tNRC 0x%x received %d times" %
                  (nrc,
                   len([nr for nr in nrs if nr.negativeResponseCode == nrc])))
        print("The following negative response codes are blacklisted: %s" %
              self.negative_response_blacklist)
        make_lined_table(data, self.get_table_entry)

    @staticmethod
    def get_table_entry(tup):
        raise NotImplementedError

    @staticmethod
    def get_session_string(session):
        return (UDS() / UDS_DSC(diagnosticSessionType=session)). \
            sprintf("%UDS_DSC.diagnosticSessionType%")

    @staticmethod
    def get_label(response,
                  positive_case="PR: PositiveResponse"):
        if response is None:
            label = "Timeout"
        elif response.service == 0x7f:
            label = response.sprintf("NR: %UDS_NR.negativeResponseCode%")
        else:
            if isinstance(positive_case, six.string_types):
                label = positive_case
            elif callable(positive_case):
                label = positive_case()
            else:
                raise Scapy_Exception("Unsupported Type for positive_case. "
                                      "Provide a string or a function.")
        return label

    @staticmethod
    def enter_session(socket, session, reset_handler=None,
                      verbose=False, **kwargs):
        if reset_handler:
            reset_handler()
        if session in [0, 1] and reset_handler:
            warning("You try to enter the defaultSession or session 0. The"
                    "reset_handler did probably already reset your ECU to "
                    "session 1.")
            return True
        req = UDS() / UDS_DSC(diagnosticSessionType=session)
        ans = socket.sr1(req, timeout=2, verbose=False, **kwargs)
        if ans is not None:
            if verbose:
                print("Try to enter session %s" % session)
                print(repr(req))
                print(repr(ans))
            return ans.service != 0x7f
        else:
            return False


class UDS_SessionEnumerator(UDS_Enumerator):
    description = "Available sessions"
    negative_response_blacklist = [0x10, 0x11, 0x12]

    def __init__(self, sock):
        super(UDS_SessionEnumerator, self).__init__(sock)
        self.sessions_visited = set()
        self.session_graph = Graph()

    def show(self, filtered=True):
        super(UDS_SessionEnumerator, self).show(filtered)
        print("The following session paths were found: %s" %
              self.get_session_paths())

    def get_session_paths(self, initial_session=1):
        paths = [Graph.dijsktra(self.session_graph, initial_session, s)
                 for s in self.sessions_visited if s != initial_session]
        return [p for p in paths if p is not None] + [[1]]

    def scan(self, session=1, session_range=range(2, 0x100),
             reset_handler=None, **kwargs):
        pkts = UDS() / UDS_DSC(diagnosticSessionType=session_range)
        if reset_handler:
            reset_handler()

        timeout = kwargs.pop("timeout", 3)
        for req in pkts:
            super(UDS_SessionEnumerator, self).scan(session, [req],
                                                    timeout=timeout,
                                                    **kwargs)
            # reset if positive response received
            try:
                last_response = self.results[-1].resp
                if last_response and last_response.service == 0x50 and \
                        reset_handler:
                    reset_handler()
            except AttributeError as e:
                warning("Reset of scan target couldn't be performed.")
                warning(e)

        self.sessions_visited.add(session)
        # get requests with positive response from this session
        reqs = [req for s, req, resp in self.results
                if s == session and resp is not None and
                req is not None and resp.service == 0x50]

        for req in reqs:
            self.session_graph.add_edge(session, req.diagnosticSessionType)
            if req.diagnosticSessionType in self.sessions_visited:
                continue
            self.scan(session=req.diagnosticSessionType,
                      reset_handler=lambda: [x() for x in
                                             [reset_handler,
                                              lambda: self.enter_session(
                                                  self.sock,
                                                  req.diagnosticSessionType,
                                                  **kwargs)]],
                      session_range=session_range, **kwargs)

    @staticmethod
    def get_table_entry(tup):
        session, req, res = tup
        label = UDS_Enumerator.get_label(res, "PR: Supported")
        return (session,
                "0x%02x: %s" % (req.diagnosticSessionType, req.sprintf(
                    "%UDS_DSC.diagnosticSessionType%")),
                label)


class UDS_ServiceEnumerator(UDS_Enumerator):
    description = "Available services and negative response per session"
    negative_response_blacklist = [0x10, 0x11]

    def scan(self, session="DefaultSession", **kwargs):
        pkts = (UDS(service=x) for x in set(x & ~0x40 for x in range(0x100)))
        super(UDS_ServiceEnumerator, self).scan(session, pkts, **kwargs)

    @staticmethod
    def get_table_entry(tup):
        session, req, res = tup
        label = UDS_Enumerator.get_label(res)
        return (session,
                "0x%02x: %s" % (req.service, req.sprintf("%UDS.service%")),
                label)


class UDS_RDBIEnumerator(UDS_Enumerator):
    description = "Readable data identifier per session"
    negative_response_blacklist = [0x10, 0x11, 0x12, 0x31]

    def scan(self, session="DefaultSession", scan_range=range(0x10000),
             **kwargs):
        pkts = (UDS() / UDS_RDBI(identifiers=[x]) for x in scan_range)
        super(UDS_RDBIEnumerator, self).scan(session, pkts, **kwargs)

    @staticmethod
    def print_information(resp):
        load = bytes(resp)[3:] if len(resp) > 3 else "No data available"
        return "PR: %s" % ((load[:17] + b"...") if len(load) > 20 else load)

    @staticmethod
    def get_table_entry(tup):
        session, req, res = tup
        label = UDS_Enumerator.get_label(
            res,
            positive_case=lambda: UDS_RDBIEnumerator.print_information(res))
        return (session,
                "0x%04x: %s" % (req.identifiers[0],
                                req.sprintf("%UDS_RDBI.identifiers%")[1:-1]),
                label)


class UDS_WDBIEnumerator(UDS_Enumerator):
    description = "Writeable data identifier"
    negative_response_blacklist = [0x10, 0x11, 0x12, 0x31]

    def scan(self, session="DefaultSession", scan_range=range(0x10000),
             rdbi_enumerator=None,
             **kwargs):

        if rdbi_enumerator is None:
            pkts = (UDS() / UDS_WDBI(dataIdentifier=x) for x in scan_range)
        elif isinstance(rdbi_enumerator, UDS_RDBIEnumerator):
            pkts = (UDS() / UDS_WDBI(dataIdentifier=res.dataIdentifier) /
                    Raw(load=bytes(res)[3:])
                    for _, _, res in rdbi_enumerator.filtered_results
                    if res.service != 0x7f and len(bytes(res)) >= 3)
        else:
            raise Scapy_Exception("rdbi_enumerator has to be an instance "
                                  "of UDS_RDBIEnumerator")
        super(UDS_WDBIEnumerator, self).scan(session, pkts, **kwargs)

    @staticmethod
    def get_table_entry(tup):
        session, req, res = tup
        label = UDS_Enumerator.get_label(res, "Writeable")
        return (session,
                "0x%04x: %s" % (req.dataIdentifier,
                                req.sprintf("%UDS_WDBI.dataIdentifier%")),
                label)


class UDS_SAEnumerator(UDS_Enumerator):
    description = "Available security seeds with access type and session"
    negative_response_blacklist = [0x10, 0x11, 0x12]

    def scan(self, session="DefaultSesion", **kwargs):
        pkts = (UDS() / UDS_SA(securityAccessType=x)
                for x in range(1, 0xff, 2))
        super(UDS_SAEnumerator, self).scan(session, pkts, **kwargs)

    @staticmethod
    def get_table_entry(tup):
        session, req, res = tup
        label = UDS_Enumerator.get_label(
            res, positive_case=lambda: "PR: %s" % res.securitySeed)
        return session, req.securityAccessType, label


class UDS_RCEnumerator(UDS_Enumerator):
    description = "Available RoutineControls and negative response per session"
    negative_response_blacklist = [0x10, 0x11, 0x31]

    def scan(self, session="DefaultSession", scan_range=range(0xffff),
             **kwargs):
        pkts = (UDS() / UDS_RC(routineControlType=2, routineIdentifier=x)
                for x in scan_range)
        super(UDS_RCEnumerator, self).scan(session, pkts, **kwargs)

    @staticmethod
    def get_table_entry(tup):
        session, req, res = tup
        label = UDS_Enumerator.get_label(res)
        return (session,
                "0x%04x: %s" % (req.routineIdentifier,
                                req.sprintf("%UDS_RC.routineIdentifier%")),
                label)


class UDS_IOCBIEnumerator(UDS_Enumerator):
    description = "Available Input Output Controls By Identifier " \
                  "and negative response per session"
    negative_response_blacklist = [0x10, 0x11, 0x31]

    def scan(self, session="DefaultSession", scan_range=range(0xffff),
             **kwargs):
        pkts = (UDS() / UDS_IOCBI(dataIdentifier=x) for x in scan_range)
        super(UDS_IOCBIEnumerator, self).scan(session, pkts, **kwargs)

    @staticmethod
    def get_table_entry(tup):
        session, req, res = tup
        label = UDS_Enumerator.get_label(res)
        return (session,
                "0x%04x: %s" % (req.dataIdentifier,
                                req.sprintf("%UDS_IOCBI.dataIdentifier%")),
                label)


class UDS_RMBAEnumerator(UDS_Enumerator):
    description = "Readable Memory Adresses " \
                  "and negative response per session"
    negative_response_blacklist = [0x10, 0x11, 0x31]

    def scan(self, session="DefaultSession", scan_range=range(0xffff),
             **kwargs):
        pkts = [UDS() / UDS_RMBA(memorySizeLen=1, memoryAddressLen=1, memoryAddress1=x, memorySize1=4) for x in [random.randint(0, 0x100) for _ in range(10)]]  # noqa: E501
        pkts += [UDS() / UDS_RMBA(memorySizeLen=2, memoryAddressLen=1, memoryAddress1=x, memorySize2=4) for x in [random.randint(0, 0x100) for _ in range(10)]]  # noqa: E501
        pkts += [UDS() / UDS_RMBA(memorySizeLen=3, memoryAddressLen=1, memoryAddress1=x, memorySize3=4) for x in [random.randint(0, 0x100) for _ in range(10)]]  # noqa: E501
        pkts += [UDS() / UDS_RMBA(memorySizeLen=4, memoryAddressLen=1, memoryAddress1=x, memorySize4=4) for x in [random.randint(0, 0x100) for _ in range(10)]]  # noqa: E501
        pkts += [UDS() / UDS_RMBA(memorySizeLen=1, memoryAddressLen=2, memoryAddress2=x, memorySize1=4) for x in [random.randint(0, 0x100) << 8 for _ in range(100)]]  # noqa: E501
        pkts += [UDS() / UDS_RMBA(memorySizeLen=2, memoryAddressLen=2, memoryAddress2=x, memorySize2=4) for x in [random.randint(0, 0x100) << 8 for _ in range(100)]]  # noqa: E501
        pkts += [UDS() / UDS_RMBA(memorySizeLen=3, memoryAddressLen=2, memoryAddress2=x, memorySize3=4) for x in [random.randint(0, 0x100) << 8 for _ in range(100)]]  # noqa: E501
        pkts += [UDS() / UDS_RMBA(memorySizeLen=4, memoryAddressLen=2, memoryAddress2=x, memorySize4=4) for x in [random.randint(0, 0x100) << 8 for _ in range(100)]]  # noqa: E501
        pkts += [UDS() / UDS_RMBA(memorySizeLen=1, memoryAddressLen=3, memoryAddress3=x, memorySize1=4) for x in [random.randint(0, 0x10000) << 8 for _ in range(100)]]  # noqa: E501
        pkts += [UDS() / UDS_RMBA(memorySizeLen=2, memoryAddressLen=3, memoryAddress3=x, memorySize2=4) for x in [random.randint(0, 0x10000) << 8 for _ in range(100)]]  # noqa: E501
        pkts += [UDS() / UDS_RMBA(memorySizeLen=3, memoryAddressLen=3, memoryAddress3=x, memorySize3=4) for x in [random.randint(0, 0x10000) << 8 for _ in range(100)]]  # noqa: E501
        pkts += [UDS() / UDS_RMBA(memorySizeLen=4, memoryAddressLen=3, memoryAddress3=x, memorySize4=4) for x in [random.randint(0, 0x10000) << 8 for _ in range(100)]]  # noqa: E501
        pkts += [UDS() / UDS_RMBA(memorySizeLen=1, memoryAddressLen=4, memoryAddress4=x, memorySize1=4) for x in [random.randint(0, 0x1000000) << 8 for _ in range(1000)]]  # noqa: E501
        pkts += [UDS() / UDS_RMBA(memorySizeLen=2, memoryAddressLen=4, memoryAddress4=x, memorySize2=4) for x in [random.randint(0, 0x1000000) << 8 for _ in range(1000)]]  # noqa: E501
        pkts += [UDS() / UDS_RMBA(memorySizeLen=3, memoryAddressLen=4, memoryAddress4=x, memorySize3=4) for x in [random.randint(0, 0x1000000) << 8 for _ in range(1000)]]  # noqa: E501
        pkts += [UDS() / UDS_RMBA(memorySizeLen=4, memoryAddressLen=4, memoryAddress4=x, memorySize4=4) for x in [random.randint(0, 0x1000000) << 8 for _ in range(1000)]]  # noqa: E501
        super(UDS_RMBAEnumerator, self).scan(session, pkts, **kwargs)

    @staticmethod
    def get_table_entry(tup):
        session, req, res = tup
        label = UDS_Enumerator.get_label(
            res, positive_case=lambda: "PR: %s" % res.dataRecord)
        return (session,
                "0x%04x" % (getattr(req,
                                    "memoryAddress%d" % req.memoryAddressLen)),
                label)


def execute_session_based_scan(sock, reset_handler, enumerator,
                               session_paths, **kwargs):
    for session_path in session_paths:
        reset_handler()
        change_successful = True
        for next_session in session_path:
            if next_session == 1:
                continue

            if not UDS_Enumerator.enter_session(
                    sock, next_session, verbose=kwargs.get("verbose", False)):
                warning("Error during session change to session %d" %
                        next_session)
                change_successful = False
                break

        current_session = session_path[-1]
        if change_successful:
            tps = None
            if current_session != 1:
                tps = UDS_TesterPresentSender(sock)
                tps.start()

            enumerator.scan(session=UDS_Enumerator.get_session_string(
                current_session), **kwargs)

            if tps:
                tps.stop()

    enumerator.show()
    return enumerator


def UDS_Scan(sock, reset_handler, scan_depth=10, **kwargs):
    reset_handler()
    sessions = UDS_SessionEnumerator(sock)
    sessions.scan(reset_handler=reset_handler)
    sessions.show()

    scan_depth -= 1
    if scan_depth == 0:
        return

    available_sessions = sessions.get_session_paths()

    execute_session_based_scan(sock, reset_handler,
                               UDS_ServiceEnumerator(sock),
                               available_sessions)

    scan_depth -= 1
    if scan_depth == 0:
        return

    rdbi_scan_range = kwargs.pop("rdbi_scan_range", range(0x10000))
    rdbi = execute_session_based_scan(sock, reset_handler,
                                      UDS_RDBIEnumerator(sock),
                                      available_sessions,
                                      scan_range=rdbi_scan_range)

    scan_depth -= 1
    if scan_depth == 0:
        return

    execute_session_based_scan(sock, reset_handler, UDS_WDBIEnumerator(sock),
                               available_sessions,
                               rdbi_enumerator=rdbi)

    scan_depth -= 1
    if scan_depth == 0:
        return

    execute_session_based_scan(sock, reset_handler,
                               UDS_RMBAEnumerator(sock),
                               available_sessions)

    scan_depth -= 1
    if scan_depth == 0:
        return

    execute_session_based_scan(sock, reset_handler,
                               UDS_RCEnumerator(sock),
                               available_sessions)

    scan_depth -= 1
    if scan_depth == 0:
        return

    execute_session_based_scan(sock, reset_handler,
                               UDS_IOCBIEnumerator(sock),
                               available_sessions)

    scan_depth -= 1
    if scan_depth == 0:
        return

    execute_session_based_scan(sock, reset_handler,
                               UDS_SAEnumerator(sock),
                               available_sessions)
