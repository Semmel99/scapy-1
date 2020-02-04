#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Markus Schroetter <project.m.schroetter@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = GMLAN Utilities
# scapy.contrib.status = loads

import time
import random
from scapy.contrib.automotive.gm.gmlan import GMLAN, GMLAN_SA, GMLAN_RD, \
    GMLAN_TD, GMLAN_PM, GMLAN_RMBA, GMLAN_RDBI, GMLAN_RDBPI, GMLAN_IDO
from scapy.contrib.automotive.enumerator import Enumerator
from scapy.config import conf
from scapy.contrib.isotp import ISOTPSocket
from scapy.error import warning, log_loading
from scapy.utils import PeriodicSenderThread


__all__ = ["GMLAN_TesterPresentSender", "GMLAN_InitDiagnostics",
           "GMLAN_GetSecurityAccess", "GMLAN_RequestDownload",
           "GMLAN_TransferData", "GMLAN_TransferPayload",
           "GMLAN_ReadMemoryByAddress", "GMLAN_BroadcastSocket",
           "GMLAN_Scan", "GMLAN_ServiceEnumerator", "GMLAN_RDBIEnumerator",
           "GMLAN_RDBPIEnumerator", "GMLAN_RMBAEnumerator"]

log_loading.info("\"conf.contribs['GMLAN']"
                 "['treat-response-pending-as-answer']\" set to True). This "
                 "is required by the GMLAN-Utils module to operate "
                 "correctly.")
try:
    conf.contribs['GMLAN']['treat-response-pending-as-answer'] = False
except KeyError:
    conf.contribs['GMLAN'] = {'treat-response-pending-as-answer': False}


class GMLAN_TesterPresentSender(PeriodicSenderThread):
    def __init__(self, sock, pkt=GMLAN(service="TesterPresent"), interval=2):
        """ Thread to send TesterPresent messages packets periodically

        Args:
            sock: socket where packet is sent periodically
            pkt: packet to send
            interval: interval between two packets
        """
        PeriodicSenderThread.__init__(self, sock, pkt, interval)


def _check_response(resp, verbose):
    if resp is None:
        if verbose:
            print("Timeout.")
        return False
    if verbose:
        resp.show()
    return resp.sprintf("%GMLAN.service%") != "NegativeResponse"


def _send_and_check_response(sock, req, timeout, verbose):
    if verbose:
        print("Sending %s" % repr(req))
    resp = sock.sr1(req, timeout=timeout, verbose=0)
    return _check_response(resp, verbose)


def GMLAN_InitDiagnostics(sock, broadcastsocket=None, timeout=None,
                          verbose=None, retry=0):
    """Send messages to put an ECU into an diagnostic/programming state.

    Args:
        sock:       socket to send the message on.
        broadcast:  socket for broadcasting. If provided some message will be
                    sent as broadcast. Recommended when used on a network with
                    several ECUs.
        timeout:    timeout for sending, receiving or sniffing packages.
        verbose:    set verbosity level
        retry:      number of retries in case of failure.

    Returns true on success.
    """
    if verbose is None:
        verbose = conf.verb
    retry = abs(retry)

    while retry >= 0:
        retry -= 1

        # DisableNormalCommunication
        p = GMLAN(service="DisableNormalCommunication")
        if broadcastsocket is None:
            if not _send_and_check_response(sock, p, timeout, verbose):
                continue
        else:
            if verbose:
                print("Sending %s as broadcast" % repr(p))
            broadcastsocket.send(p)
        time.sleep(0.05)

        # ReportProgrammedState
        p = GMLAN(service="ReportProgrammingState")
        if not _send_and_check_response(sock, p, timeout, verbose):
            continue
        # ProgrammingMode requestProgramming
        p = GMLAN() / GMLAN_PM(subfunction="requestProgrammingMode")
        if not _send_and_check_response(sock, p, timeout, verbose):
            continue
        time.sleep(0.05)

        # InitiateProgramming enableProgramming
        # No response expected
        p = GMLAN() / GMLAN_PM(subfunction="enableProgrammingMode")
        if verbose:
            print("Sending %s" % repr(p))
        sock.send(p)
        time.sleep(0.05)
        return True
    return False


def GMLAN_GetSecurityAccess(sock, keyFunction, level=1, timeout=None,
                            verbose=None, retry=0):
    """Authenticate on ECU. Implements Seey-Key procedure.

    Args:
        sock:        socket to send the message on.
        keyFunction: function implementing the key algorithm.
        level:       level of access
        timeout:     timeout for sending, receiving or sniffing packages.
        verbose:     set verbosity level
        retry:       number of retries in case of failure.

    Returns true on success.
    """
    if verbose is None:
        verbose = conf.verb
    retry = abs(retry)

    if level % 2 == 0:
        warning("Parameter Error: Level must be an odd number.")
        return False

    while retry >= 0:
        retry -= 1

        request = GMLAN() / GMLAN_SA(subfunction=level)
        if verbose:
            print("Requesting seed..")
        resp = sock.sr1(request, timeout=timeout, verbose=0)
        if not _check_response(resp, verbose):
            if verbose:
                print("Negative Response.")
            continue

        seed = resp.securitySeed
        if seed == 0:
            if verbose:
                print("ECU security already unlocked. (seed is 0x0000)")
            return True

        keypkt = GMLAN() / GMLAN_SA(subfunction=level + 1,
                                    securityKey=keyFunction(seed))
        if verbose:
            print("Responding with key..")
        resp = sock.sr1(keypkt, timeout=timeout, verbose=0)
        if resp is None:
            if verbose:
                print("Timeout.")
            continue
        if verbose:
            resp.show()
        if resp.sprintf("%GMLAN.service%") == "SecurityAccessPositiveResponse":   # noqa: E501
            if verbose:
                print("SecurityAccess granted.")
            return True
        # Invalid Key
        elif resp.sprintf("%GMLAN.service%") == "NegativeResponse" and \
                resp.sprintf("%GMLAN.returnCode%") == "InvalidKey":
            if verbose:
                print("Key invalid")
            continue

    return False


def GMLAN_RequestDownload(sock, length, timeout=None, verbose=None, retry=0):
    """Send RequestDownload message.

    Usually used before calling TransferData.

    Args:
        sock:       socket to send the message on.
        length:     value for the message's parameter 'unCompressedMemorySize'.
        timeout:    timeout for sending, receiving or sniffing packages.
        verbose:    set verbosity level.
        retry:      number of retries in case of failure.

    Returns true on success.
    """
    if verbose is None:
        verbose = conf.verb
    retry = abs(retry)

    while retry >= 0:
        # RequestDownload
        pkt = GMLAN() / GMLAN_RD(memorySize=length)
        resp = sock.sr1(pkt, timeout=timeout, verbose=0)
        if _check_response(resp, verbose):
            return True
        retry -= 1
        if retry >= 0 and verbose:
            print("Retrying..")
    return False


def GMLAN_TransferData(sock, addr, payload, maxmsglen=None, timeout=None,
                       verbose=None, retry=0):
    """Send TransferData message.

    Usually used after calling RequestDownload.

    Args:
        sock:       socket to send the message on.
        addr:       destination memory address on the ECU.
        payload:    data to be sent.
        maxmsglen:  maximum length of a single iso-tp message. (default:
                    maximum length)
        timeout:    timeout for sending, receiving or sniffing packages.
        verbose:    set verbosity level.
        retry:      number of retries in case of failure.

    Returns true on success.
    """
    if verbose is None:
        verbose = conf.verb
    retry = abs(retry)
    startretry = retry

    scheme = conf.contribs['GMLAN']['GMLAN_ECU_AddressingScheme']
    if addr < 0 or addr >= 2**(8 * scheme):
        warning("Error: Invalid address " + hex(addr) + " for scheme " +
                str(scheme))
        return False

    # max size of dataRecord according to gmlan protocol
    if maxmsglen is None or maxmsglen <= 0 or maxmsglen > (4093 - scheme):
        maxmsglen = (4093 - scheme)

    for i in range(0, len(payload), maxmsglen):
        retry = startretry
        while True:
            if len(payload[i:]) > maxmsglen:
                transdata = payload[i:i + maxmsglen]
            else:
                transdata = payload[i:]
            pkt = GMLAN() / GMLAN_TD(startingAddress=addr + i,
                                     dataRecord=transdata)
            resp = sock.sr1(pkt, timeout=timeout, verbose=0)
            if _check_response(resp, verbose):
                break
            retry -= 1
            if retry >= 0:
                if verbose:
                    print("Retrying..")
            else:
                return False

    return True


def GMLAN_TransferPayload(sock, addr, payload, maxmsglen=None, timeout=None,
                          verbose=None, retry=0):
    """Send data by using GMLAN services.

    Args:
        sock:       socket to send the data on.
        addr:       destination memory address on the ECU.
        payload:    data to be sent.
        maxmsglen:  maximum length of a single iso-tp message. (default:
                    maximum length)
        timeout:    timeout for sending, receiving or sniffing packages.
        verbose:    set verbosity level.
        retry:      number of retries in case of failure.

    Returns true on success.
    """
    if not GMLAN_RequestDownload(sock, len(payload), timeout=timeout,
                                 verbose=verbose, retry=retry):
        return False
    if not GMLAN_TransferData(sock, addr, payload, maxmsglen=maxmsglen,
                              timeout=timeout, verbose=verbose, retry=retry):
        return False
    return True


def GMLAN_ReadMemoryByAddress(sock, addr, length, timeout=None,
                              verbose=None, retry=0):
    """Read data from ECU memory.

    Args:
        sock:       socket to send the data on.
        addr:       source memory address on the ECU.
        length:     bytes to read
        timeout:    timeout for sending, receiving or sniffing packages.
        verbose:    set verbosity level.
        retry:      number of retries in case of failure.

    Returns the bytes read.
    """
    if verbose is None:
        verbose = conf.verb
    retry = abs(retry)

    scheme = conf.contribs['GMLAN']['GMLAN_ECU_AddressingScheme']
    if addr < 0 or addr >= 2**(8 * scheme):
        warning("Error: Invalid address " + hex(addr) + " for scheme " +
                str(scheme))
        return None

    # max size of dataRecord according to gmlan protocol
    if length <= 0 or length > (4094 - scheme):
        warning("Error: Invalid length " + hex(length) + " for scheme " +
                str(scheme) + ". Choose between 0x1 and " + hex(4094 - scheme))
        return None

    while retry >= 0:
        # RequestDownload
        pkt = GMLAN() / GMLAN_RMBA(memoryAddress=addr, memorySize=length)
        resp = sock.sr1(pkt, timeout=timeout, verbose=0)
        if _check_response(resp, verbose):
            return resp.dataRecord
        retry -= 1
        if retry >= 0 and verbose:
            print("Retrying..")
    return None


def GMLAN_BroadcastSocket(interface):
    """Returns a GMLAN broadcast socket using interface."""
    return ISOTPSocket(interface, sid=0x101, did=0x0, basecls=GMLAN,
                       extended_addr=0xfe, padding=True)


class GMLAN_Enumerator(Enumerator):
    """ Base class for UDS Enumerators

    Args:
        sock: socket where enumeration takes place
    """
    @property
    def filtered_results(self):
        return [r for r in super(GMLAN_Enumerator, self).filtered_results
                if r.resp.service != 0x7f or r.resp.returnCode
                not in self.negative_response_blacklist]

    def show_negative_response_details(self):
        nrs = [r.resp for r in self.results if r.resp is not None and
               r.resp.service == 0x7f]
        nrcs = set([nr.returnCode for nr in nrs])
        print("These negative response codes were received %s" % nrcs)
        for nrc in nrcs:
            print("\tNRC 0x%x received %d times" %
                  (nrc,
                   len([nr for nr in nrs if nr.returnCode == nrc])))

    @staticmethod
    def get_table_entry(tup):
        raise NotImplementedError

    @staticmethod
    def get_label(response,
                  positive_case="PR: PositiveResponse",
                  negative_case="NR: NegativeResponse", ):
        return Enumerator.get_label(
            response, positive_case,
            response.sprintf("NR: %GMLAN_NR.returnCode%"))

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
        if session == 2:
            return GMLAN_InitDiagnostics(socket, timeout=2, verbose=verbose)
        else:
            return False


class GMLAN_ServiceEnumerator(GMLAN_Enumerator):
    description = "Available services and negative response per session"
    negative_response_blacklist = [0x11]

    def scan(self, session="DefaultSession", **kwargs):
        services = set(x & ~0x40 for x in range(0x100))
        services.remove(0x10)  # Remove InitiateDiagnosticOperation service
        services.remove(0x20)  # Remove ReturnToNormalOperation
        services.remove(0x28)  # Remove DisableNormalCommunication service
        services.remove(0xa5)  # Remove ProgrammingMode service
        pkts = (GMLAN(service=x) for x in services)
        super(GMLAN_ServiceEnumerator, self).scan(session, pkts, **kwargs)

    @staticmethod
    def get_table_entry(tup):
        session, req, res = tup
        label = GMLAN_Enumerator.get_label(res)
        return (session,
                "0x%02x: %s" % (req.service, req.sprintf("%GMLAN.service%")),
                label)


class GMLAN_RDBIEnumerator(GMLAN_Enumerator):
    description = "Readable data identifier per session"
    negative_response_blacklist = [0x11, 0x12, 0x31]

    def scan(self, session="DefaultSession", scan_range=range(0x100),
             **kwargs):
        pkts = (GMLAN() / GMLAN_RDBI(dataIdentifier=x) for x in scan_range)
        super(GMLAN_RDBIEnumerator, self).scan(session, pkts, **kwargs)

    @staticmethod
    def print_information(resp):
        load = bytes(resp)[3:] if len(resp) > 3 else "No data available"
        return "PR: %s" % ((load[:17] + b"...") if len(load) > 20 else load)

    @staticmethod
    def get_table_entry(tup):
        session, req, res = tup
        label = GMLAN_Enumerator.get_label(
            res,
            positive_case=lambda: GMLAN_RDBIEnumerator.print_information(res))
        return (session,
                "0x%04x: %s" % (req.dataIdentifier,
                                req.sprintf("%GMLAN_RDBI.dataIdentifier%")),
                label)


class GMLAN_RDBPIEnumerator(GMLAN_Enumerator):
    description = "Readable parameter identifier per session"
    negative_response_blacklist = [0x11, 0x12, 0x31]

    def scan(self, session="DefaultSession", scan_range=range(0x10000),
             **kwargs):
        pkts = (GMLAN() / GMLAN_RDBPI(identifiers=[x]) for x in scan_range)
        super(GMLAN_RDBPIEnumerator, self).scan(session, pkts, **kwargs)

    @staticmethod
    def get_table_entry(tup):
        session, req, res = tup
        label = GMLAN_Enumerator.get_label(
            res,
            positive_case=lambda: GMLAN_RDBIEnumerator.print_information(res))
        return (session,
                "0x%04x: %s" % (req.identifiers[0],
                                req.sprintf(
                                    "%GMLAN_RDBPI.identifiers%")[1:-1]),
                label)


class GMLAN_RMBAEnumerator(GMLAN_Enumerator):
    description = "Readable Memory Adresses " \
                  "and negative response per session"
    negative_response_blacklist = [0x10, 0x11, 0x31]

    def scan(self, session="DefaultSession", scan_range=range(2000),
             **kwargs):
        addrs = [random.randint(0, 0xffffffff) // 4 for _ in scan_range]
        pkts = (GMLAN() / GMLAN_RMBA(memoryAddress=x, memorySize=0x10) for x in
                addrs)
        super(GMLAN_RMBAEnumerator, self).scan(session, pkts, **kwargs)

    @staticmethod
    def get_table_entry(tup):
        session, req, res = tup
        label = GMLAN_Enumerator.get_label(
            res, positive_case=lambda: "PR: %s" % res.dataRecord)
        return session, "0x%04x" % req.memoryAddress, label


# ########################## SESSION HELPER ###################################

def switchToDiagnosticSession(socket):
    ans = socket.sr1(GMLAN() / GMLAN_IDO(subfunction=2), timeout=5,
                     verbose=False)
    if ans is not None and ans.service == 0x7f:
        ans.show()
    return ans is not None and ans.service != 0x7f


def execute_session_based_scan(sock, reset_handler, enumerator,
                               bcast_sock=None,
                               keyfunction=lambda x: x, **kwargs):
    verbose = kwargs.get("verbose", False)

    # ## SCAN ###
    reset_handler()
    enumerator.scan(session="DefaultSession")

    # ## SCAN ###
    reset_handler()
    tps = GMLAN_TesterPresentSender(bcast_sock)
    tps.start()
    enumerator.scan(session="DefaultSession+TP")
    tps.stop()

    # ## SCAN ###
    reset_handler()
    tps = GMLAN_TesterPresentSender(bcast_sock)
    tps.start()
    switched = switchToDiagnosticSession(sock)
    if switched:
        enumerator.scan(session="DiagnosticSession")
    tps.stop()

    # ## SCAN ###
    reset_handler()
    tps = GMLAN_TesterPresentSender(bcast_sock)
    tps.start()
    switched = GMLAN_InitDiagnostics(sock, timeout=20, verbose=verbose)
    if switched:
        enumerator.scan(session="ProgrammingSession")
    tps.stop()

    # ## SCAN ###
    reset_handler()
    tps = GMLAN_TesterPresentSender(bcast_sock)
    tps.start()
    time.sleep(15)
    sw1 = GMLAN_InitDiagnostics(sock, timeout=20, verbose=verbose)
    sw2 = GMLAN_GetSecurityAccess(sock, keyfunction, verbose=verbose)
    if sw1 and sw2:
        enumerator.scan(session="ProgrammingSession SA")
    tps.stop()

    # ## SCAN ###
    reset_handler()
    tps = GMLAN_TesterPresentSender(bcast_sock)
    tps.start()
    time.sleep(15)
    sw1 = GMLAN_InitDiagnostics(sock, timeout=20, verbose=verbose)
    sw2 = GMLAN_GetSecurityAccess(sock, keyfunction, verbose=verbose)
    sw3 = GMLAN_RequestDownload(sock, 0x10, verbose=verbose, timeout=15)
    if sw1 and sw2 and sw3:
        enumerator.scan(session="ProgrammingSession SA RD")
    tps.stop()

    enumerator.show()
    return enumerator


def GMLAN_Scan(sock, reset_handler, scan_depth=10, **kwargs):
    reset_handler()

    execute_session_based_scan(sock, reset_handler,
                               GMLAN_ServiceEnumerator(sock), **kwargs)

    scan_depth -= 1
    if scan_depth == 0:
        return

    execute_session_based_scan(sock, reset_handler,
                               GMLAN_RDBIEnumerator(sock), **kwargs)

    scan_depth -= 1
    if scan_depth == 0:
        return

    execute_session_based_scan(sock, reset_handler,
                               GMLAN_RMBAEnumerator(sock), **kwargs)

    scan_depth -= 1
    if scan_depth == 0:
        return

    execute_session_based_scan(sock, reset_handler,
                               GMLAN_RDBPIEnumerator(sock), **kwargs)

    scan_depth -= 1
    if scan_depth == 0:
        return
