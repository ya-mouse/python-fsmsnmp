import socket
import logging
import pysnmp.proto.api
from pyasn1.codec.ber import encoder, decoder
from struct import pack, unpack
from time import time

from fsmsock.proto import UdpTransport

class SnmpUdpClient(UdpTransport):
    def __init__(self, host, interval, version, community, variables, port=161, split_by=None):
        self._version = {
            '1':  pysnmp.proto.api.protoVersion1,
            '2c': pysnmp.proto.api.protoVersion2c,
        }.get(version, pysnmp.proto.api.protoVersion1)
        self._community = community
        self._vars = variables
        self._buf = None
        self._bufidx = 0
        self._split_by = split_by if split_by else len(self._vars)
        # Protocol verison to use
        self._pmod = pysnmp.proto.api.protoModules[self._version]
        super().__init__(host, interval, port)

    def _build_buf(self):
        self._buf = []
        self._bufidx = 0
        cnt = len(self._vars)
        while cnt > 0:
            toread = min(cnt, self._split_by)
            off = len(self._vars) - cnt
            msg = self._build_msg(self._vars[off:off+toread])
            self._buf.append(msg)
            cnt -= self._split_by

    def _build_msg(self, variables):
        # Build PDU
        pdu = self._pmod.GetRequestPDU()
        self._pmod.apiPDU.setDefaults(pdu)
        self._pmod.apiPDU.setVarBinds(pdu, ( (v, self._pmod.Null('')) for v in variables) )
        # Build message
        msg = self._pmod.Message()
        self._pmod.apiMessage.setDefaults(msg)
        self._pmod.apiMessage.setCommunity(msg, self._community)
        self._pmod.apiMessage.setPDU(msg, pdu)
        return encoder.encode(msg)

    def send_buf(self):
        if not len(self._buf):
            return 0
        return self._write(self._buf[self._bufidx])

    def process_data(self, data, tm = None):
        self._retries = 0

        # Process data
        if tm is None:
            tm = time()
        while data:
            msg, data = decoder.decode(data, asn1Spec=self._pmod.Message())
            pdu = self._pmod.apiMessage.getPDU(msg)
            # Check for SNMP errors reported
            error = self._pmod.apiPDU.getErrorStatus(pdu)
            if error:
                if error == 1: # tooBig:
                    self._split_by //= 2
                    logging.warning("{}: `tooBig' occuried, split vars by {}".format(self._host, self._split_by))
                    self._build_buf()
                    return False
                else:
                    logging.critical("{}: SNMP error: {}".format(self._host, error.prettyPrint()))
            else:
                try:
                    for oid, val in self._pmod.apiPDU.getVarBinds(pdu):
                        self.on_data(oid, val, tm)
                except Exception as e:
                    logging.critical(e)

        self._bufidx = (self._bufidx + 1) % len(self._buf)
        if self._bufidx == 0:
            self._state = self.READY
            self.stop()
            return False
        return True

    def on_data(self, oid, val, tm):
        pass
