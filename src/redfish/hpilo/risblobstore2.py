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
"""Base implementation for interaction with blob store interface"""

#---------Imports---------

import os
import sys
import struct

from ctypes import (c_char_p, c_ubyte, c_uint, cdll, POINTER,
                    create_string_buffer)
from redfish.hpilo.rishpilo import (HpIlo)

if os.name == 'nt':
    from ctypes import windll
else:
    from _ctypes import dlclose

#---------End of imports---------

#-----------------------Error Returns----------------------

class UnexpectedResponseError(Exception):
    """Raise when we get data that we don't expect from iLO"""
    pass

class HpIloError(Exception):
    """Raised when iLO returns non-zero error code"""
    pass

class Blob2CreateError(Exception):
    """Raised when create operation fails"""
    pass

class Blob2InfoError(Exception):
    """Raised when create operation fails"""
    pass

class Blob2ReadError(Exception):
    """Raised when read operation fails"""
    pass

class Blob2WriteError(Exception):
    """Raised when write operation fails"""
    pass

class Blob2DeleteError(Exception):
    """Raised when delete operation fails"""
    pass

class Blob2FinalizeError(Exception):
    """Raised when finalize operation fails"""
    pass

class Blob2ListError(Exception):
    """Raised when list operation fails"""
    pass

class BlobNotFoundError(Exception):
    """Raised when blob not found in key/namespace"""
    pass

class ChifDllMissingError(Exception):
    """Raised when unable to obtain hprest_chif dll handle"""
    pass

#----------------------------------------------------------

#-------------------Helper functions-------------------------

class BlobReturnCodes(object):
    """Blob store return codes.

    SUCCESS           success
    NOTFOUND          blob name not found
    NOTMODIFIED       call did not perform the operation

    """

    SUCCESS = 0
    NOTFOUND = 12
    NOTMODIFIED = 20

class BlobStore2(object):
    """Blob store 2 class"""
    def __init__(self):
        self.channel = HpIlo()

    def __del__(self):
        """Blob store 2 close channel function"""
        self.channel.close()

    def create(self, key, namespace):
        """Create the blob

        :param key: The blob key to create.
        :type key: str.
        :param namespace: The blob namespace to create the key in.
        :type namespace: str.

        """
        lib = self.gethprestchifhandle()
        lib.create_not_blobentry.argtypes = [c_char_p, c_char_p]
        lib.create_not_blobentry.restype = POINTER(c_ubyte)

        name = create_string_buffer(key)
        namespace = create_string_buffer(namespace)

        ptr = lib.create_not_blobentry(name, namespace)
        data = ptr[:lib.size_of_createRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data, lib.size_of_createResponse())

        if len(resp) > lib.size_of_createResponse():
            raise Blob2CreateError("create response larger than expected")

        if len(resp) < lib.size_of_createResponse():
            raise Blob2CreateError("create response smaller than expected")

        errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
        if not (errorcode == BlobReturnCodes.SUCCESS or \
                                    errorcode == BlobReturnCodes.NOTMODIFIED):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return resp

    def get_info(self, key, namespace):
        """Get information for a particular blob

        :param key: The blob key to retrieve.
        :type key: str.
        :param namespace: The blob namespace to retrieve the key from.
        :type namespace: str.

        """
        lib = self.gethprestchifhandle()
        lib.get_info.argtypes = [c_char_p, c_char_p]
        lib.get_info.restype = POINTER(c_ubyte)

        name = create_string_buffer(key)
        namespace = create_string_buffer(namespace)

        ptr = lib.get_info(name, namespace)
        data = ptr[:lib.size_of_infoRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data, lib.size_of_infoResponse())

        if len(resp) > lib.size_of_infoResponse():
            raise Blob2InfoError("info response larger than expected")

        if len(resp) < lib.size_of_infoResponse():
            raise Blob2InfoError("info response smaller than expected")

        errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
        if errorcode == BlobReturnCodes.NOTFOUND:
            raise BlobNotFoundError(key, namespace)

        if not (errorcode == BlobReturnCodes.SUCCESS or \
                                    errorcode == BlobReturnCodes.NOTMODIFIED):
            raise HpIloError(errorcode)

        response = resp[lib.size_of_responseHeaderBlob():]

        self.unloadchifhandle(lib)

        return response

    def read(self, key, namespace):
        """Read a particular blob

        :param key: The blob key to be read.
        :type key: str.
        :param namespace: The blob namespace to read the key from.
        :type namespace: str.

        """
        lib = self.gethprestchifhandle()
        maxread = lib.max_read_size()
        readsize = lib.size_of_readRequest()
        readhead = lib.size_of_responseHeaderBlob()

        self.unloadchifhandle(lib)

        blob_info = self.get_info(key, namespace)
        blobsize = struct.unpack("<I", bytes(blob_info[0:4]))[0]

        bytes_read = 0
        data = bytearray()

        while bytes_read < blobsize:
            if (maxread - readsize) < (blobsize - bytes_read):
                count = maxread - readsize
            else:
                count = blobsize - bytes_read

            read_block_size = bytes_read
            recvpkt = self.read_fragment(key, namespace, read_block_size, count)

            newreadsize = readhead + 4
            bytesread = struct.unpack("<I", bytes(recvpkt[readhead:\
                                                            (newreadsize)]))[0]
            data.extend(recvpkt[newreadsize:newreadsize + bytesread])
            bytes_read += bytesread

        return data

    def read_fragment(self, key, namespace, offset=0, count=1):
        """Fragmented version of read function for large blobs

        :param key: The blob key to be read.
        :type key: str.
        :param namespace: The blob namespace to read the key from.
        :type namespace: str.
        :param offset: The data offset for the current fragmented read.
        :type key: int.
        :param count: The data count for the current fragmented read.
        :type namespace: int.

        """
        lib = self.gethprestchifhandle()
        lib.read_fragment.argtypes = [c_uint, c_uint, c_char_p, c_char_p]
        lib.read_fragment.restype = POINTER(c_ubyte)

        name = create_string_buffer(key)
        namespace = create_string_buffer(namespace)

        ptr = lib.read_fragment(offset, count, name, namespace)
        data = ptr[:lib.size_of_readRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data, lib.size_of_readResponse())

        if len(resp) < lib.size_of_responseHeaderBlob():
            raise Blob2ReadError("read fragment response smaller than expected")

        resp = resp + "\0" * (lib.size_of_readResponse() - len(resp))

        return resp

    def write(self, key, namespace, data=None):
        """Write a particular blob

        :param key: The blob key to be written.
        :type key: str.
        :param namespace: The blob namespace to write the key in.
        :type namespace: str.
        :param data: The blob data to be written.
        :type data: str.

        """
        lib = self.gethprestchifhandle()
        maxwrite = lib.max_write_size()
        writesize = lib.size_of_writeRequest()

        self.unloadchifhandle(lib)

        if data:
            data_length = len(data)
            bytes_written = 0

            while bytes_written < data_length:
                if (maxwrite - writesize) < (data_length - bytes_written):
                    count = maxwrite - writesize
                else:
                    count = data_length - bytes_written

                write_blob_size = bytes_written

                self.write_fragment(key, namespace=namespace, \
                            data=data[write_blob_size:write_blob_size+count], \
                            offset=write_blob_size, count=count)

                bytes_written += count

        return self.finalize(key, namespace=namespace)

    def write_fragment(self, key, namespace, data=None, offset=0, count=1):
        """Fragmented version of write function for large blobs

        :param key: The blob key to be written.
        :type key: str.
        :param namespace: The blob namespace to write the key in.
        :type namespace: str.
        :param data: The blob data to be written to blob.
        :type data: str.
        :param offset: The data offset for the current fragmented write.
        :type key: int.
        :param count: The data count for the current fragmented write.
        :type count: int.

        """
        lib = self.gethprestchifhandle()
        lib.write_fragment.argtypes = [c_uint, c_uint, c_char_p, c_char_p]
        lib.write_fragment.restype = POINTER(c_ubyte)

        name = create_string_buffer(key)
        namespace = create_string_buffer(namespace)

        ptr = lib.write_fragment(offset, count, name, namespace)
        sendpacket = ptr[:lib.size_of_writeRequest()]

        dataarr = bytearray(sendpacket)
        dataarr.extend(buffer(data))

        resp = self._send_receive_raw(dataarr, lib.size_of_writeResponse())

        if len(resp) < lib.size_of_writeResponse():
            raise Blob2WriteError("write fragment response larger than " \
                                                                    "expected")

        errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
        if not (errorcode == BlobReturnCodes.SUCCESS or\
                                    errorcode == BlobReturnCodes.NOTMODIFIED):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return resp

    def delete(self, key, namespace):
        """Delete the blob

        :param key: The blob key to be deleted.
        :type key: str.
        :param namespace: The blob namespace to delete the key from.
        :type namespace: str.

        """
        lib = self.gethprestchifhandle()
        lib.delete_blob.argtypes = [c_char_p, c_char_p]
        lib.delete_blob.restype = POINTER(c_ubyte)

        name = create_string_buffer(key)
        namespace = create_string_buffer(namespace)

        ptr = lib.delete_blob(name, namespace)
        data = ptr[:lib.size_of_deleteRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data, lib.size_of_deleteResponse())

        if len(resp) > lib.size_of_deleteResponse():
            raise Blob2DeleteError("delete response larger than expected")

        if len(resp) < lib.size_of_deleteResponse():
            raise Blob2DeleteError("delete response smaller than expected")

        errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
        if not (errorcode == BlobReturnCodes.SUCCESS or\
                                    errorcode == BlobReturnCodes.NOTMODIFIED):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return errorcode

    def list(self, namespace):
        """List operation to retrieve all blobs in a given namespace

        :param namespace: The blob namespace to retrieve the keys from.
        :type namespace: str.

        """
        lib = self.gethprestchifhandle()
        lib.list_blob.argtypes = [c_char_p]
        lib.list_blob.restype = POINTER(c_ubyte)

        namespace = create_string_buffer(namespace)

        ptr = lib.list_blob(namespace)
        data = ptr[:lib.size_of_listRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data, lib.size_of_listResponse())

        if len(resp) < lib.size_of_listResponseFixed():
            raise Blob2ListError("list response smaller than expected")

        errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
        if not (errorcode == BlobReturnCodes.SUCCESS or\
                                    errorcode == BlobReturnCodes.NOTMODIFIED):
            raise HpIloError(errorcode)

        resp = resp + "\0" * (lib.size_of_listResponse() - len(resp))

        self.unloadchifhandle(lib)

        return resp

    def finalize(self, key, namespace):
        """Finalize the blob

        :param key: The blob key to be finalized.
        :type key: str.
        :param namespace: The blob namespace to finalize the key in.
        :type namespace: str.

        """
        lib = self.gethprestchifhandle()
        lib.finalize_blob.argtypes = [c_char_p, c_char_p]
        lib.finalize_blob.restype = POINTER(c_ubyte)

        name = create_string_buffer(key)
        namespace = create_string_buffer(namespace)

        ptr = lib.finalize_blob(name, namespace)
        data = ptr[:lib.size_of_finalizeRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data, lib.size_of_finalizeResponse())

        if len(resp) > lib.size_of_finalizeResponse():
            raise Blob2FinalizeError("finalize response smaller than expected")

        if len(resp) < lib.size_of_finalizeResponse():
            raise Blob2FinalizeError("finalize response smaller than expected")

        errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
        if not (errorcode == BlobReturnCodes.SUCCESS or\
                                    errorcode == BlobReturnCodes.NOTMODIFIED):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return errorcode

    def rest_immediate(self, req_data, rqt_key="RisRequest", \
                                        rsp_key="RisResponse", \
                                        rsp_namespace="volatile"):
        """Read/write blob via immediate operation

        :param req_data: The blob data to be read/written.
        :type req_data: str.
        :param rqt_key: The blob key to be used for the request data.
        :type rqt_key: str.
        :param rsp_key: The blob key to be used for the response data.
        :type rsp_key: str.
        :param rsp_namespace: The blob namespace to retrieve the response from.
        :type rsp_namespace: str.

        """
        lib = self.gethprestchifhandle()

        if len(req_data) < (lib.size_of_restImmediateRequest() + \
                                                        lib.max_write_size()):
            lib.rest_immediate.argtypes = [c_uint, c_char_p, c_char_p]
            lib.rest_immediate.restype = POINTER(c_ubyte)

            name = create_string_buffer(rsp_key)
            namespace = create_string_buffer(rsp_namespace)

            ptr = lib.rest_immediate(len(req_data), name, namespace)
            sendpacket = ptr[:lib.size_of_restImmediateRequest()]
            mode = False
        else:
            self.create(rqt_key, rsp_namespace)
            self.write(rqt_key, rsp_namespace, req_data)

            lib.rest_immediate_blobdesc.argtypes = [c_char_p, c_char_p, \
                                                                    c_char_p]
            lib.rest_immediate_blobdesc.restype = POINTER(c_ubyte)

            name = create_string_buffer(rqt_key)
            namespace = create_string_buffer(rsp_namespace)
            rspname = create_string_buffer(rsp_key)

            ptr = lib.rest_immediate_blobdesc(name, rspname, namespace)
            sendpacket = ptr[:lib.size_of_restBlobRequest()]
            mode = True

        data = bytearray(sendpacket)

        if not mode:
            data.extend(req_data)

        resp = self._send_receive_raw(data, lib.size_of_restResponse())

        errorcode = struct.unpack("<I", bytes(resp[8:12]))[0]
        if errorcode == BlobReturnCodes.NOTFOUND:
            raise BlobNotFoundError(rsp_key, rsp_namespace)

        recvmode = struct.unpack("<I", bytes(resp[12:16]))[0]

        fixdlen = lib.size_of_restResponseFixed()
        response = resp[fixdlen:struct.unpack("<I", bytes(resp[16:20]))[0] + \
                                                                        fixdlen]

        tmpresponse = None
        if errorcode == BlobReturnCodes.SUCCESS and not mode:
            if recvmode == 0:
                tmpresponse = ''.join(map(chr, response))
        elif errorcode == BlobReturnCodes.NOTMODIFIED and not mode:
            if recvmode == 0:
                tmpresponse = ''.join(map(chr, response))
        elif errorcode == BlobReturnCodes.SUCCESS:
            if recvmode == 0:
                tmpresponse = ''.join(map(chr, response))
        elif recvmode == 0:
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        if not tmpresponse and recvmode == 1:
            tmpresponse = self.read(rsp_key, rsp_namespace)
            self.delete(rsp_key, rsp_namespace)
        else:
            self.delete(rsp_key, rsp_namespace)

        return tmpresponse

    def mount_blackbox(self):
        """Operation to mount the blackbox partition"""
        lib = self.gethprestchifhandle()
        lib.blackbox_media_mount.argtypes = []
        lib.blackbox_media_mount.restype = POINTER(c_ubyte)

        ptr = lib.blackbox_media_mount()
        data = ptr[:lib.size_of_embeddedMediaRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data, lib.size_of_embeddedMediaResponse())

        errorcode = resp[12]
        if not (errorcode == BlobReturnCodes.SUCCESS or\
                                    errorcode == BlobReturnCodes.NOTMODIFIED):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return resp

    def absaroka_media_mount(self):
        """Operation to mount the absaroka repo partition"""
        lib = self.gethprestchifhandle()
        lib.absaroka_media_mount.argtypes = []
        lib.absaroka_media_mount.restype = POINTER(c_ubyte)

        ptr = lib.absaroka_media_mount()
        data = ptr[:lib.size_of_embeddedMediaRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data, lib.size_of_embeddedMediaResponse())

        errorcode = resp[12]
        if not (errorcode == BlobReturnCodes.SUCCESS or\
                                    errorcode == BlobReturnCodes.NOTMODIFIED):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return resp

    def gaius_media_mount(self):
        """Operation to mount the gaius media partition"""
        lib = self.gethprestchifhandle()
        lib.gaius_media_mount.argtypes = []
        lib.gaius_media_mount.restype = POINTER(c_ubyte)

        ptr = lib.gaius_media_mount()
        data = ptr[:lib.size_of_embeddedMediaRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data, lib.size_of_embeddedMediaResponse())

        errorcode = resp[12]
        if not (errorcode == BlobReturnCodes.SUCCESS or\
                                    errorcode == BlobReturnCodes.NOTMODIFIED):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return resp

    def media_unmount(self):
        """Operation to unmount the media partition"""
        lib = self.gethprestchifhandle()
        lib.media_unmount.argtypes = []
        lib.media_unmount.restype = POINTER(c_ubyte)

        ptr = lib.media_unmount()
        data = ptr[:lib.size_of_embeddedMediaRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data, lib.size_of_embeddedMediaResponse())

        errorcode = resp[12]
        if not (errorcode == BlobReturnCodes.SUCCESS or\
                                    errorcode == BlobReturnCodes.NOTMODIFIED):
            raise HpIloError(errorcode)

        self.unloadchifhandle(lib)

        return resp

    def _send_receive_raw(self, indata, datarecv=0):
        """Send and receive raw function for blob operations

        :param indata: The data to be sent to blob operation.
        :type indata: str.
        :param datarecv: The expected size of the blob operation response.
        :type datarecv: int.

        """
        resp = self.channel.send_receive_raw(indata, 3, datarecv)
        return resp

    @staticmethod
    def gethprestchifhandle():
        """Multi platform handle for chif hprest library"""
        try:
            if os.name == 'nt':
                libpath = BlobStore2.checkincurrdirectory('hprest_chif.dll')
                libhandle = cdll.LoadLibrary(libpath)
            else:
                try:
                    libpath = BlobStore2.checkincurrdirectory('hprest_chif_dev.so')
                    libhandle = cdll.LoadLibrary(libpath)
                except:
                    libpath = BlobStore2.checkincurrdirectory('hprest_chif.so')
                    libhandle = cdll.LoadLibrary(libpath)
        except Exception as excp:
            raise ChifDllMissingError(excp)

        return libhandle

    @staticmethod
    def checkincurrdirectory(libname):
        """Check if the library is present in current directory."""
        libpath = libname
        if os.path.isfile(os.path.join(os.path.split(sys.executable)[0], libpath)):
            libpath = os.path.join(os.path.split(sys.executable)[0], libpath)
        elif os.path.isfile(os.path.join(os.getcwd(), libpath)):
            libpath = os.path.join(os.getcwd(), libpath)
        return libpath

    @staticmethod
    def unloadchifhandle(lib):
        """Release a handle on the chif hprest library

        :param lib: The library handle provided by loading the chif library.
        :type lib: library handle.

        """
        try:
            libhandle = lib._handle

            if os.name == 'nt':
                windll.kernel32.FreeLibrary(None, handle=libhandle)
            else:
                dlclose(libhandle)
        except Exception:
            pass
