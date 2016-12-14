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
import logging
from redfish import redfish_client, rest_client
from redfish.ris.rmc_helper import UnableToObtainIloVersionError
#---------End of imports---------

LOGGER = logging.getLogger(__name__)

class Typesandpathdefines(object):
    """Global types and path definitions class"""
    def __init__(self):
        self.url = None
        self.defs = None
        self.ilogen = None
        self.flagiften = False

    def getgen(self, url=None, logger=None):
        """Function designed to verify the servers platform

        :param url: The URL to perform the request on.
        :type url: str.
        :param logger: The logger handler.
        :type logger: str.

        """
        self.url = url

        try:
            redfishclient = redfish_client(base_url=self.url, \
                               username=None, password=None, \
                               default_prefix="/redfish/v1/", is_redfish=True)
            response = redfishclient.get(path="/redfish/v1/")
        except Exception as excp:
            try:
                restclient = rest_client(base_url=self.url, username=None, \
                                     password=None, default_prefix="/rest/v1")
                response = restclient.get(path="/rest/v1")
            except Exception as excep:
                logger = logger if not logger else LOGGER
                if type(excep) != type(excp):
                    logger.error(u"Gen get rest error:"+str(excep)+u"\n")
                raise excp

        self.ilogen = None

        try:
            self.ilogen = response.dict["Oem"]["Hp"]["Manager"][0]\
                                                                ["ManagerType"]
        except:
            self.ilogen = response.dict["Oem"]["Hpe"]["Manager"][0]\
                                                                ["ManagerType"]

        try:
            self.ilogen = self.ilogen.split(' ')[-1]
            self.flagiften = False
            if int(self.ilogen) >= 5:
                self.flagiften = True
        except:
            raise UnableToObtainIloVersionError("Unable to find the iloversion")

        if self.flagiften:
            self.defs = Definevalstenplus()
        else:
            self.defs = DefinevalsNine()

class Definevals(object):
    """Class for setting platform dependent variables"""
    def __init__(self):
        pass

class Definevalstenplus(Definevals):
    """Platform dependent variables"""
    # pylint: disable=too-many-instance-attributes
    # As a defines classt this will need all the attributes
    def __init__(self):
        self.oemhp = u"Hpe"

        self.oempath = u"/Oem/Hpe"
        self.startpath = u"/redfish/v1/"
        self.systempath = u"/redfish/v1/Systems/1/"
        self.managerpath = u"/redfish/v1/Managers/1/"
        self.biospath = u"/redfish/v1/systems/1/bios/"
        self.addlicensepath = u"/redfish/v1/Managers/1/LicenseService/"
        self.accountspath = u"/redfish/v1/AccountService/Accounts/"
        self.federationpath = u"/redfish/v1/Managers/1/FederationGroups/"

        self.biostype = u"Bios."
        self.hpeskmtype = u"HpeESKM."
        self.hpcommontype = u"HpeCommon"
        self.hpilossotype = u"HpeiLOSSO."
        self.hpsecureboot = u"SecureBoot."
        self.logservicetype = u"#LogService."
        self.hphttpscerttype = u"HpeHttpsCert."
        self.snmpservice = u"HpeiLOSnmpService."
        self.attributenametype = u"AttributeName"
        self.hpilodatetimetype = u"HpeiLODateTime."
        self.attributeregtype = u"#AttributeRegistry."
        self.hpilofirmwareupdatetype = u"UpdateService."
        self.resourcedirectorytype = u"HpeiLOResourceDirectory."
        self.hpilofederationgrouptype = u"HpeiLOFederationGroup."
        self.managernetworkservicetype = u"ManagerNetworkProtocol."
        self.schemafilecollectiontype = u"#JsonSchemaFileCollection."
        self.hpilolicensecollectiontype = u"HpeiLOLicenseCollection."
        self.hpiloactivehealthsystemtype = u"#HpeiLOActiveHealthSystem."
        self.hpiscsisoftwareinitiatortype = u"HpeiSCSISoftwareInitiator."
        self.hpilofederationgrouptypecoll = u"HpeiLOFederationGroupCollection."        
        self.bootoverridetargettype = u"BootSourceOverrideTarget@Redfish.AllowableValues"
        self.messageregistrytype = u"#MessageRegistry."

        self.typestring = u"@odata.type"
        self.hrefstring = u"@odata.id"
        self.collectionstring = u"Members"
        self.biossettingsstring = u"@Redfish.Settings"
        self.attname = u"AttributeName"

        self.isgen9 = False
        self.isgen10 = True
        self.flagforrest = False
        super(Definevalstenplus, self).__init__()

    def redfishchange(self):
        """Function to update redfish variables"""
        pass


class DefinevalsNine(Definevals):
    """Platform dependent variables"""
    # pylint: disable=too-many-instance-attributes
    # As a defines classt this will need all the attributes
    def __init__(self):
        self.oemhp = u"Hp"

        self.oempath = u"/Oem/Hp"
        self.startpath = u"/rest/v1"
        self.systempath = u"/rest/v1/Systems/1"
        self.managerpath = u"/rest/v1/Managers/1"
        self.biospath = u"/rest/v1/systems/1/bios"
        self.addlicensepath = u"/rest/v1/Managers/1/LicenseService"
        self.accountspath = u"/rest/v1/AccountService/Accounts"
        self.federationpath = u"/rest/v1/Managers/1/FederationGroups"

        self.biostype = u"HpBios."
        self.hpeskmtype = u"HpESKM."
        self.hpcommontype = u"HpCommon"
        self.hpilossotype = u"HpiLOSSO."
        self.snmpservice = u"SnmpService."
        self.attributenametype = u"Name"
        self.logservicetype = u"LogService."
        self.hpsecureboot = u"HpSecureBoot."
        self.hphttpscerttype = u"HpHttpsCert."
        self.hpilodatetimetype = u"HpiLODateTime."
        self.hpilofirmwareupdatetype = u"HpiLOFirmwareUpdate."
        self.resourcedirectorytype = u"HpiLOResourceDirectory."
        self.hpilofederationgrouptype = u"HpiLOFederationGroup."
        self.attributeregtype = u"HpBiosAttributeRegistrySchema."
        self.schemafilecollectiontype = u"#SchemaFileCollection."
        self.managernetworkservicetype = u"ManagerNetworkService."
        self.hpiloactivehealthsystemtype = u"HpiLOActiveHealthSystem."
        self.messageregistrytype = u"MessageRegistry."
        self.hpilolicensecollectiontype = None
        self.hpilofederationgrouptypecoll = None
        self.bootoverridetargettype = u"BootSourceOverrideSupported"
        self.hpiscsisoftwareinitiatortype = u"HpiSCSISoftwareInitiator"

        self.typestring = u"Type"
        self.hrefstring = u"href"
        self.collectionstring = u"Items"
        self.biossettingsstring = u"SettingsResult"
        self.attname = u"Name"

        self.isgen9 = True
        self.isgen10 = False
        self.flagforrest = True
        super(DefinevalsNine, self).__init__()

    def redfishchange(self):
        """Function to update redfish variables"""
        self.startpath = u"/redfish/v1/"
        self.systempath = u"/redfish/v1/Systems/1/"
        self.managerpath = u"/redfish/v1/Managers/1/"
        self.biospath = u"/redfish/v1/systems/1/bios/"
        self.addlicensepath = u"/redfish/v1/Managers/1/LicenseService/"

        self.typestring = u"@odata.type"
        self.hrefstring = u"@odata.id"
        self.collectionstring = u"Members"

        self.logservicetype = u"#LogService."
        self.hpiloactivehealthsystemtype = u"#HpiLOActiveHealthSystem."
        self.hpilolicensecollectiontype = u"HpiLOLicenseCollection."
        self.hpilofederationgrouptypecoll = u"HpiLOFederationGroupCollection."
        self.managernetworkservicetype = u"ManagerNetworkProtocol."

        self.flagforrest = False
