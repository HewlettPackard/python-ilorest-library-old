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
"""Typedefs implementation"""

#---------Imports---------
from ilorest import redfish_client, rest_client
#---------End of imports---------

#TODO: need to add the real LOGGER included in other files

class typesandpathdefines(object):
    """Global types and path definitions class"""
    def __init__(self):
        self.url = None
        self.defs = None
        self.ilogen = None
        self.flagiften = False

    def getGen(self, url=None, logger=None):
        """Function designed to verify the servers platform

        :param url: The URL to perform the request on.
        :type url: str.
        :param logger: The logger handler.
        :type logger: str.

        """
        self.url = url

        try:
            redfishclient = redfish_client(base_url=self.url, \
                   username=None, password=None, default_prefix="/redfish/v1")
            response = redfishclient.get(path="/redfish/v1")
        except Exception as excp:
            try:
                restclient = rest_client(base_url=self.url, username=None, \
                                     password=None, default_prefix="/rest/v1")
                response = restclient.get(path="/rest/v1")
            except Exception as excep:
                if logger:
                    logger.error(u"getGen rest error:"+str(excep)+u"\n")
                    logger.error(u"getGen redfish error:"+str(excp)+u"\n")
                raise excp

        self.ilogen = None

        try:
            self.ilogen = response.dict["Oem"]["Hp"]["Manager"][0]\
                                                                ["ManagerType"]
        except:
            self.ilogen = response.dict["Oem"]["Hpe"]["Manager"][0]\
                                                                ["ManagerType"]

        if self.ilogen is None:
            #TODO: need to fix this raise to a more useful error
            raise

        self.ilogen = self.ilogen.split(' ')[-1]

        self.flagiften = False
        if int(self.ilogen) >= 5:
            self.flagiften = True

        if self.flagiften:
            self.defs = definevalstenplus()
        else:
            self.defs = definevalsNine()

class definevals(object):
    """Class for setting platform dependent variables"""
    def __init__(self):
        pass

#TODO: need to fix the variable names to pass pylint check
class definevalstenplus(definevals):
    """Platform dependent variables"""
    def __init__(self):
        self.OemHp = u"Hpe"

        self.oempath = u"/Oem/Hpe"
        self.systempath = u"/redfish/v1/Systems/1/"
        self.ManagerPath = u"/redfish/v1/Managers/1/"
        self.BiosPath = u"/redfish/v1/systems/1/bios/"
        self.AddLicensePath = u"/redfish/v1/Managers/1/LicenseService/"
        self.AccountsPath = u"/redfish/v1/AccountService/Accounts/"
        self.FederationPath = u"/redfish/v1/Managers/1/FederationGroups/"

        self.BiosType = u"HpeBios."
        self.HpESKMType = u"HpeESKM."
        self.HpCommonType = u"HpeCommon"
        self.HpiLOSSOType = u"HpeiLOSSO."
        self.HpSecureBoot = u"HpeSecureBoot."
        self.LogServiceType = u"#LogService."
        self.HpHttpsCertType = u"HpeHttpsCert."
        self.SnmpService = u"HpeiLOSnmpService."
        self.HpiLODateTimeType = u"HpeiLODateTime."
        self.HpiLOFirmwareUpdateType = u"HpeiLOFirmwareUpdate."
        self.ResourceDirectoryType = u"HpeiLOResourceDirectory."
        self.HpiLOFederationGroupType = u"HpeiLOFederationGroup."
        self.ManagerNetworkServiceType = u"ManagerNetworkProtocol."
        self.SchemaFileCollectionType = u"#JsonSchemaFileCollection."
        self.HpiLOLicenseCollectionType = u"HpeiLOLicenseCollection."
        self.HpiLOActiveHealthSystemType = u"#HpeiLOActiveHealthSystem."
        self.HpiLOFederationGroupTypeColl = u"HpeiLOFederationGroupCollection."
        self.MessageRegistryType = u"#MessageRegistry."

        self.typestring = u"@odata.type"
        self.hrefstring = u"@odata.id"
        self.collectionstring = u"Members"

        self.IsGen9 = False
        self.IsGen10 = True
        self.flagforrest = False
        super(definevalstenplus, self).__init__()

    def redfishchange(self):
        """Function to update redfish variables"""
        pass

    def CorrectHpStr(self, typestr):
        if typestr.startswith(u'Hpe'):
            return typestr
        elif typestr.startswith(u'Hp'):
            return u"Hpe"+typestr[2:]
        else:
            return typestr

class definevalsNine(definevals):
    """Platform dependent variables"""
    def __init__(self):
        self.OemHp = u"Hp"

        self.oempath = u"/Oem/Hp"
        self.systempath = u"/rest/v1/Systems/1"
        self.ManagerPath = u"/rest/v1/Managers/1"
        self.BiosPath = u"/rest/v1/systems/1/bios"
        self.AddLicensePath = u"/rest/v1/Managers/1/LicenseService"
        self.AccountsPath = u"/rest/v1/AccountService/Accounts"
        self.FederationPath = u"/rest/v1/Managers/1/FederationGroups"

        self.BiosType = u"HpBios."
        self.HpESKMType = u"HpESKM."
        self.HpCommonType = u"HpCommon"
        self.HpiLOSSOType = u"HpiLOSSO."
        self.SnmpService = u"SnmpService."
        self.LogServiceType = u"LogService."
        self.HpSecureBoot = u"HpSecureBoot."
        self.HpHttpsCertType = u"HpHttpsCert."
        self.HpiLODateTimeType = u"HpiLODateTime."
        self.HpiLOFirmwareUpdateType = u"HpiLOFirmwareUpdate."
        self.ResourceDirectoryType = u"HpiLOResourceDirectory."
        self.HpiLOFederationGroupType = u"HpiLOFederationGroup."
        self.ManagerNetworkServiceType = u"ManagerNetworkService."
        self.SchemaFileCollectionType = u"#SchemaFileCollection."
        self.HpiLOActiveHealthSystemType = u"HpiLOActiveHealthSystem."
        self.MessageRegistryType = u"MessageRegistry."

        self.typestring = u"Type"
        self.hrefstring = u"href"
        self.collectionstring = u"Items"

        self.IsGen9 = True
        self.IsGen10 = False
        self.flagforrest = True
        super(definevalsNine, self).__init__()

    def redfishchange(self):
        """Function to update redfish variables"""
        self.systempath = u"/redfish/v1/Systems/1/"
        self.ManagerPath = u"/redfish/v1/Managers/1/"
        self.BiosPath = u"/redfish/v1/systems/1/bios/"
        self.AddLicensePath = u"/redfish/v1/Managers/1/LicenseService/"

        self.typestring = u"@odata.type"
        self.hrefstring = u"@odata.id"
        self.collectionstring = u"Members"

        self.LogServiceType = u"#LogService."
        self.HpiLOActiveHealthSystemType = u"#HpiLOActiveHealthSystem."
        self.HpiLOLicenseCollectionType = u"HpiLOLicenseCollection."
        self.HpiLOFederationGroupTypeColl = u"HpiLOFederationGroupCollection."
        self.ManagerNetworkServiceType = u"ManagerNetworkProtocol."

        self.flagforrest = False

    def CorrectHpStr(self, typestr):
        """Function to update HP to HPE types"""
        if typestr.startswith(u'Hpe'):
            return u"Hp"+typestr[3:]
        else:
            return typestr

