###
# Copyright 2016 Hewlett Packard Enterprise, Inc. All rights reserved.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#  http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###

# -*- coding: utf-8 -*-
"""Base implementation for interaction with the iLO interface"""

#---------Imports---------

import os
import sys
import time
import select
import ctypes

#---------End of imports---------

class BlobReturnCodes(object):
    """Blob store return codes.

    SUCCESS           success

    """

    SUCCESS = 0


class HpIloInitialError(Exception):
    """Raised when error during initialization of iLO Chif channel"""
    pass

class HpIloReadError(Exception):
    """Raised when errors encountered when reading from iLO"""
    pass

class HpIloSendReceiveError(Exception):
    """Raised when errors encountered when reading form iLO after sending"""
    pass

class HpIloChifPacketExchangeError(Exception):
    """Raised when errors encountered when exchanging chif packet"""
    pass


class HpIlo(object):
    """Base class of interaction with iLO"""
    if os.name != 'nt':
        # Newer versions of hpilo kernel module support a configurable max_ccb
        MAX_CCB = '/sys/module/hpilo/parameters/max_ccb'
        CHANNEL = '/dev/hpilo/d0ccb'

    def __init__(self):
        if os.name == 'nt':
            fhandle = ctypes.c_void_p()

            self.libhandle = ctypes.windll.kernel32.LoadLibraryA('cpqci')
            self.dll = ctypes.WinDLL('', handle=self.libhandle)
            self.dll.ChifInitialize(None)

            self.dll.ChifCreate.argtypes = [ctypes.c_void_p]
            self.dll.ChifCreate.restype = ctypes.c_uint32

            try:
                status = self.dll.ChifCreate(ctypes.byref(fhandle))
                if status != BlobReturnCodes.SUCCESS:
                    raise HpIloInitialError("Error %s occurred while "\
                                            "trying to open a channel "\
                                            "to iLO" % status)

                self.fhandle = fhandle
                self.dll.ChifSetRecvTimeout(self.fhandle, 120000)
            except Exception, excp:
                self.unload()
                raise excp
        else:
            if os.path.exists(HpIlo.MAX_CCB):
                fhandle = open(HpIlo.MAX_CCB, 'r')

                for line in fhandle:
                    start = int(line) - 1

                fhandle.close()
            else:
                #otherwise the default number of channels is 8
                start = 7

            self.file = HpIlo.CHANNEL + str(start)
            self.cmd = None
            self.svc = None
            self.response = None

            while True:
                try:
                    self.fhandle = os.open(self.file, os.O_NONBLOCK | \
                                                os.O_EXCL | os.O_RDWR, 0666)
                    self.len = 0
                    self.seq = 0
                    return
                except Exception:
                    start = start - 1
                    self.file = HpIlo.CHANNEL + str(start)

                    if start < 0:
                        raise HpIloInitialError("iLO channel could not be " \
                                                                "allocated.")

    def write_raw(self, data):
        """Send data to iLO.  Use this if you have already pre-packed and"""
        """ formatted data

        :param data: bytearray of data to send
        :type data: bytearray

        """
        return os.write(self.fhandle, data)

    def read_raw(self, timeout=5):
        """Read data from iLO. Use this if you need the response as is"""
        """ (without any parse)

        :param timeout: time to wait for iLO response
        :type timeout: int (seconds)

        """
        try:
            pkt = bytearray()
            status = select.select([self.fhandle], [], [], timeout)

            if status != ([self.fhandle], [], []) and timeout > 0:
                raise HpIloReadError("iLO is not responding")

            if status != ([self.fhandle], [], []) and timeout == 0:
                return pkt

            pkt.extend(os.read(self.fhandle, 8096))
            self.response = pkt[4] + 256*pkt[5]

            return pkt
        except Exception, excp:
            raise HpIloReadError("%s : %s" % (excp, sys.exc_info()[0]))

    def chif_packet_exchange(self, data, datarecv):
        """ Windows only function for handling chif packet exchange

        :param data: data to be sent for packet exchange
        :type data: str
        :param datarecv: expected size of the response
        :type datarecv: int

        """
        buff = "".join(map(chr, data))
        buff = ctypes.create_string_buffer("".join(map(chr, data)))

        error = ctypes.c_uint()
        recbuff = ctypes.create_string_buffer(datarecv)

        error = self.dll.ChifPacketExchange(self.fhandle, ctypes.byref(buff),\
                                             ctypes.byref(recbuff), datarecv)
        if error != BlobReturnCodes.SUCCESS:
            self.close()
            self.unload()
            raise HpIloChifPacketExchangeError("Error %s occurred while "\
                                               "exchange chif packet" % error)

        pkt = bytearray()

        if datarecv is None:
            pkt.extend(recbuff)
        else:
            pkt.extend(recbuff[:datarecv])

        return pkt

    def send_receive_raw(self, data, retries=3, datarecv=None):
        """ Windows only function for proper send receive retry protocol

        :param data: data to be sent for packet exchange
        :type data: str
        :param retries: number of retries for reading data from iLO
        :type retries: int
        :param datarecv: expected size of the response
        :type datarecv: int

        """
        tries = 0

        while tries < retries:
            try:
                if os.name == 'nt':
                    resp = self.chif_packet_exchange(data, datarecv)
                else:
                    retlen = self.write_raw(data)
                    if retlen != len(data):
                        raise ValueError()

                    resp = self.read_raw(120)

                return resp
            except Exception:
                time.sleep(1)

                if tries == (retries - 1):
                    raise

            tries += 1

        raise HpIloSendReceiveError("iLO not responding")

    def close(self):
        """Chif close function"""
        try:
            if os.name == 'nt':
                self.dll.ChifClose(self.fhandle)
            else:
                os.close(self.fhandle)
        except Exception:
            pass

    def unload(self):
        """ Windows only
            Chif unload function """
        try:
            del self.dll
            ctypes.windll.kernel32.FreeLibrary(self.libhandle)
        except Exception:
            pass

    def __del__(self):
        """Chif delete function"""
        self.close()

        if os.name == 'nt':
            self.unload()

