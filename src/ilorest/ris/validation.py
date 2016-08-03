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
"""RIS Schema classes"""

# ---------Imports---------

import os
import re
import sys
import json
import locale
import zipfile
import logging
import textwrap
import validictory

from .sharedtypes import JSONEncoder
from ilorest.rest.v1_helper import (RisObject)

# ---------End of imports---------


# ---------Debug logger---------

LOGGER = logging.getLogger(__name__)

# ---------End of debug logger---------


class ValidationError(Exception):
    """Validation Class Error"""
    pass


class SchemaValidationError(ValidationError):
    """Schema Validation Class Error"""
    pass


class RegistryValidationError(ValidationError):
    """Registration Validation Class Error"""
    def __init__(self, msg, regentry=None, selector=None):
        super(RegistryValidationError, self).__init__(msg)
        self.reg = regentry
        self.sel = selector


class UnknownValidatorError(Exception):
    """Raised when we find an attribute type that we don't know how to"""
    """ validate. """


class ValidationManager(object):
    """Keep track of all the schemas and registries and provides helpers"""
    """ to simplify validation """
    def __init__(self, local_path, bios_local_path, romfamily=None, \
                biosversion=None, iloversion=None, monolith=None, defines=None):
        super(ValidationManager, self).__init__()

        defaultilopath = None
        defaultbiospath = None
        schemamainfolder = None

        if float(iloversion) < 4.210:
            if os.name == 'nt':
                defaultilopath = r".\hp-rest-classes-ilo4"
                defaultbiospath = r".\hp-rest-classes-bios"
                schemamainfolder = os.path.dirname(sys.executable)
            else:
                defaultilopath = "/usr/share/hprest/hp-rest-classes-ilo4"
                defaultbiospath = "/usr/share/hprest/hp-rest-classes-bios"
                schemamainfolder = "/usr/share/hprest/"

            # iLO schema location defaults
            if not local_path:
                if not os.path.isdir(defaultilopath):
                    ilozip = self.getiloziplocation(schemamainfolder, \
                                                                    iloversion)

                    if ilozip and os.path.exists(ilozip):
                        with zipfile.ZipFile(os.path.join(schemamainfolder, \
                                                        ilozip), "r") as zfile:
                            zfile.extractall(os.path.join(schemamainfolder, \
                                                        "hp-rest-classes-ilo4"))

                        local_path = os.path.join(schemamainfolder, \
                                                        u'hp-rest-classes-ilo4')
                    else:
                        raise SchemaValidationError(\
                                    u'No valid iLO schema zip file found.\n' \
                                    'Please refer to our documentation for ' \
                                    'further instructions on downloading the' \
                                    ' appropriate schemas.')
                else:
                    local_path = defaultilopath
            else:
                if not os.path.isdir(local_path):
                    raise SchemaValidationError(u"iLO schema directory '%s' "
                                                "doesn't exist" % local_path)

            # bios schema location defaults
            if not bios_local_path:
                if not os.path.isdir(defaultbiospath):
                    bioszip = self.getbiosziplocation(romfamily, \
                                                  schemamainfolder, biosversion)
                    if bioszip and os.path.exists(bioszip):
                        with zipfile.ZipFile(
                            os.path.join(schemamainfolder, bioszip), "r") as \
                                                                        zfile:
                            zfile.extractall(os.path.join(schemamainfolder, \
                                                        "hp-rest-classes-bios"))

                        bios_local_path = os.path.join(schemamainfolder, \
                                                        u'hp-rest-classes-bios')
                    else:
                        raise SchemaValidationError(u'No valid BIOS schema ' \
                                    'zip file found.\nPlease refer to our ' \
                                    'documentation for further instructions ' \
                                    'on downloading the appropriate schemas.')
                else:
                    bios_local_path = defaultbiospath
            else:
                if not os.path.isdir(bios_local_path):
                    raise SchemaValidationError(u"Bios schema directory '%s' " \
                                            "doesn't exist" % bios_local_path)
        else:
            if monolith.is_redfish:
                local_path = "/redfish/v1/Schemas/"
                bios_local_path = "/redfish/v1/Registries/"
            else:
                local_path = "/rest/v1/Schemas"
                bios_local_path = "/rest/v1/Registries"

        # iLO schema and registry lists
        self._schema_locations = list()
        self._classes = list()
        self._registry_locations = list()
        self._classes_registry = list()

        # iLO schema and registry lists
        self._bios_schema_locations = list()
        self._bios_classes = list()
        self._bios_registry_locations = list()
        self._bios_classes_registry = list()

        # iLO and base error messages
        self._ilo_messages = list()
        self._base_messages = list()
        self._hpcommon_messages = list()
        self._iloevents_messages = list()

        #type and path defines object
        self.defines = defines
        # error
        self._errors = list()

        #strings for v1/redfish
        if monolith.is_redfish:
            self._schemaid = ["/redfish/v1/schemas", "Members"]
            self._regid = ["/redfish/v1/registries", "Members"]
        else:
            self._schemaid = ["/rest/v1/schemas", "Items"]
            self._regid = ["/rest/v1/registries", "Items"]

        if local_path:
            self.add_location(schema_path=local_path, monolith=monolith)
            self.add_location(registry_path=local_path, monolith=monolith)

        if bios_local_path:
            self.add_location(schema_path=bios_local_path, biossection=True, \
                                                            monolith=monolith)
            self.add_location(registry_path=bios_local_path, biossection=True, \
                                                            monolith=monolith)

    def getbiosziplocation(self, romfamily, schemadir, biosversion):
        """Helper function for BIOS zip location from schema directory

        :param romfamily: the current systems rom family.
        :type romfamily: str.
        :param schemadir: the current configuration schema directory.
        :type schemadir: str.
        :param biosversion: the current system BIOS version.
        :type biosversion: str.

        """
        foundfile = None
        currentver = None

        tempstr = "hp-rest-classes-bios-" + romfamily + "-" + biosversion

        for _, _, filenames in os.walk(schemadir):
            for filename in filenames:
                if tempstr in filename:
                    regentry = re.compile('%s(.*?).zip' % tempstr)
                    mentry = regentry.search(filename)

                    if mentry and currentver:
                        if currentver < mentry.group(1):
                            foundfile = filename
                            currentver = mentry.group(1)
                    elif mentry and not currentver:
                        foundfile = filename
                        currentver = mentry.group(1)

        if foundfile:
            return os.path.join(schemadir, foundfile)
        else:
            return None

    def getiloziplocation(self, schemadir, iloversion):
        """Helper function for iLO zip location from schema directory

        :param schemadir: the current configuration schema directory.
        :type schemadir: str.
        :param iloversion: the current system iLO version.
        :type iloversion: str.

        """
        if float(iloversion) < 4.210:
            iloversion = u'2.00'

        tempstr = "hp-rest-classes-ilo4-" + iloversion.replace(".", "")

        for _, _, filenames in os.walk(schemadir):
            for filename in filenames:
                if tempstr in filename:
                    return os.path.join(schemadir, filename)

        return None

    def add_location(self, schema_path=None, registry_path=None, \
                                            biossection=False, monolith=None):
        """Add schema_path and registry_path to the list of locations to"""
        """ search for schemas and registries

        :param schema_path: directory or URL where schemas are located.
        :type  schema_path: str.
        :param registry_path: directory or URL where registries are located.
        :type registry_path: str.
        :param biossection: flag to determine if within BIOS section.
        :type biossection: str.
        :param monolith: full data model retrieved from server.
        :type monolith: dict.

        """
        if schema_path:
            if not biossection:
                self._schema_locations.append(schema_path)
                self._update_location_map(monolith=monolith)
            else:
                self._bios_schema_locations.append(schema_path)
                self._update_location_map(biossection=True, monolith=monolith)
        elif registry_path:
            if not biossection:
                self._registry_locations.append(registry_path)
                self._update_location_map(registries=True, monolith=monolith)
            else:
                self._bios_registry_locations.append(registry_path)
                self._update_location_map(biossection=True, registries=True, \
                                                            monolith=monolith)
        else:
            raise ValueError(u"'schema_path' and 'registry_path' " \
                                                                "are undefined")

    def _update_location_map(self, biossection=False, registries=False, \
                                                                monolith=None):
        """Searches locations to build a map of type to filename

        :param biossection: flag to determine if within BIOS section.
        :type biossection: str.
        :param registries: flag to determine if within registries section.
        :type registries: boolean.
        :param monolith: full data model retrieved from server.
        :type monolith: dict.

        """
        locationslist = list()
        pathjoinstr = None

        if not registries:
            pathjoinstr = "Schemas"
            if not biossection:
                locationslist = self._schema_locations
            else:
                locationslist = self._bios_schema_locations
        else:
            pathjoinstr = "Registries"
            if not biossection:
                locationslist = self._registry_locations
            else:
                locationslist = self._bios_registry_locations

        for location in locationslist:
            if monolith:
                self.new_load_file(monolith, root=location, \
                               biossection=biossection, registries=registries)
            elif self._is_local(location):
                # need to set the executable bit on all SCEXEs
                for root, _, filenames in os.walk(os.path.join(location,
                                                               pathjoinstr)):
                    for filename in filenames:
                        fqpath = os.path.abspath(os.path.join(\
                                              os.path.normpath(root), filename))

                        if self.load_file(fqpath, root=location, \
                              biossection=biossection, registries=registries):
                            LOGGER.info("Loaded schema mapping '%s'", fqpath)

    def new_load_file(self, monolith, root=None, biossection=False, \
                                                            registries=False):
        """Loads the types from monolith.

        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        :param root: pointer to the root of the load.
        :type root: class obj.
        :param biossection: flag to determine if within BIOS section.
        :type biossection: str.
        :param registries: flag to determine if within registries section.
        :type registries: boolean.

        """
        classesdataholder = []

        for itemtype in monolith.types:
            if itemtype.startswith(self.defines.defs.SchemaFileCollectionType)\
                                    or itemtype.startswith("Collection.") and \
                                    u'Instances' in monolith.types[itemtype]:
                for instance in monolith.types[itemtype][u'Instances']:
                    if self._schemaid[0] in instance.resp.request.path.\
                                            lower() or self._regid[0] in \
                                            instance.resp.request.path.lower():
                        if not registries and self._schemaid[0] in \
                                            instance.resp.request.path.lower():
                            if classesdataholder:
                                if self._schemaid[1] in instance.resp.dict:
                                    classesdataholder[0][self._schemaid[1]].\
                                                    extend(instance.resp.dict\
                                                           [self._schemaid[1]])
                            else:
                                classesdataholder.append(instance.resp.dict)
                        elif registries and self._regid[0] in \
                                            instance.resp.request.path.lower():
                            if classesdataholder:
                                if monolith.is_redfish:
                                    classesdataholder[0][self._regid[1]].\
                                                    extend(instance.resp.dict\
                                                           [self._regid[1]])
                            else:
                                classesdataholder.append(instance.resp.dict)

        if classesdataholder:
            classesdataholder = classesdataholder[0]

        try:
            if monolith._typestring in classesdataholder and ('Collection.' in \
                                    classesdataholder[monolith._typestring] or \
                                    (self.defines.defs.SchemaFileCollectionType\
                                    in classesdataholder[monolith._typestring] \
                                    and monolith.is_redfish)):
                newclass = Classes.parse(classesdataholder)
                newclass.set_root(root)

                if not registries:
                    if not biossection:
                        self._classes.append(newclass)
                    else:
                        self._bios_classes.append(newclass)
                else:
                    if not biossection:
                        self._classes_registry.append(newclass)
                    else:
                        self._bios_classes_registry.append(newclass)
        except BaseException:
            pass
        else:
            pass

    def load_file(self, filepath, root=None, biossection=False, \
                                            registries=False, datareturn=False):
        """Loads the types from filepath.

        :param filepath: path to a file to load, local or URL.
        :type filepath: str.
        :param root: root path used to reconstruct full file paths.
        :type root: str.
        :param biossection: flag to determine if within BIOS section.
        :type biossection: str.
        :param registries: flag to determine if within registries section.
        :type registries: boolean.
        :param datareturn: flag to determine if the raw data should be returned.
        :type datareturn: boolean.

        """
        result = False
        if os.path.isfile(filepath):
            try:
                filehand = open(filepath, 'r')
                data = json.load(filehand)
                if datareturn:
                    return data

                if u'Type' in data and data[u'Type'] == 'Collection.1.0.0':
                    if biossection and registries:
                        itemsreturn = self.bios_helper_function(data, root)
                        data["Items"] = itemsreturn

                    newclass = Classes.parse(data)
                    newclass.set_root(root)

                    if not registries:
                        if not biossection:
                            self._classes.append(newclass)
                        else:
                            self._bios_classes.append(newclass)
                    else:
                        if not biossection:
                            self._classes_registry.append(newclass)
                        else:
                            self._bios_classes_registry.append(newclass)

                    result = True
            except BaseException:
                pass
            else:
                pass
            finally:
                filehand.close()

        return result

    def bios_helper_function(self, data, root):
        """Helper function for BIOS schemas

        :param data: current retrieved data for BIOS.
        :type data: str.
        :param root: root path used to reconstruct full file paths.
        :type root: str.

        """
        folderentries = data["links"]
        datareturn = list()

        for entry in folderentries["Member"]:
            joinstr = entry["href"]

            if os.name == 'nt' and joinstr[0] == "/":
                joinstr = joinstr.replace("/", "\\")[1:]
            elif joinstr[0] == "/":
                joinstr = joinstr[1:]

            for root, _, filenames in os.walk(os.path.join(root, joinstr)):
                for filename in filenames:
                    fqpath = os.path.abspath(os.path.join(\
                                              os.path.normpath(root), filename))
                    datareturn.append(self.load_file(fqpath, root=root, \
                         biossection=True, registries=True, datareturn=True))
                    LOGGER.info("Loaded schema mapping '%s'", fqpath)

        return datareturn

    def validate(self, item, selector=None, currdict=None, monolith=None, \
                        newarg=None, checkall=False, regloc=None, attrreg=None):
        """Search for matching schemas and attribute registries and"""
        """ ensure that item is valid.

        :param item: the item to be validated.
        :type item: str.
        :param selector: the type selection for the get operation.
        :type selector: str.
        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :param checkall: flag to determine if check all should be enabled.
        :type checkall: boolean.
        :param regloc: path to registry location.
        :type regloc: str.

        """
        if regloc and not attrreg:
            attrreg = RepoRegistryEntry(regloc)
        elif not attrreg:
            attrreg = self.find_schema(schname=item[monolith._typestring])

        if attrreg:
            try:
                tempvalue = attrreg.validate(item, self._errors, \
                                        selector=selector, currdict=currdict, \
                                        monolith=monolith, newarg=newarg, \
                                        checkall=checkall)
            except:
                return attrreg

            if tempvalue is True:
                return False
            elif tempvalue:
                self._errors = tempvalue

        return True

    def bios_validate(self, item, regname, selector=None, currdict=None, \
                                                checkall=False, monolith=None):
        """BIOS Search for matching schemas and attribute registries and"""
        """ ensure that item is valid

        :param item: the item to be validated.
        :type item: str.
        :param regname: string containing the registry name.
        :type regname: str.
        :param selector: the type selection for the get operation.
        :type selector: str.
        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param checkall: flag to determine if check all should be enabled.
        :type checkall: boolean.
        :param monolith: full data model retrieved from server.
        :type monolith: dict.

        """
        attrreg = self.find_bios_registry(regname=regname)
        if attrreg:
            tempvalue = attrreg.validate_bios_version(item, self._errors, \
                                      selector=selector, currdict=currdict, \
                                      checkall=checkall, monolith=monolith)

            if tempvalue == 'readonly':
                return tempvalue
            elif tempvalue == 'unique':
                return tempvalue
            elif tempvalue:
                self._errors = tempvalue

        return True

    def bios_info(self, item, regname, selector):
        """BIOS Search for matching schemas and attribute registries and"""
        """ ensure that item is valid

        :param item: the item to be validated.
        :type item: str.
        :param regname: string containing the registry name.
        :type regname: str.
        :param selector: the type selection for the get operation.
        :type selector: str.

        """
        attrreg = self.find_bios_registry(regname=regname)

        if attrreg:
            if attrreg.validate_bios_version(item, self._errors, \
                                                            selector=selector):
                return False

        return True

    def find_schema(self, schname):
        """Searches through all locations and returns the first schema"""
        """ found for the provided type

        :param schname: string containing the schema name.
        :type schname: str.

        """
        for cls in self._classes:
            found = cls.find_schema(schname=schname)
            if found:
                return found
        return None

    def find_registry(self, regname):
        """Searches through all locations and returns the first registry"""
        """ found for the provided type

        :param regname: string containing the registry name.
        :type regname: str.

        """
        for cls in self._classes_registry:
            found = cls.find_registry(regname=regname)
            if found:
                return found

        return None

    def find_bios_registry(self, regname):
        """Searches through all locations and returns the first schema found"""
        """ for the provided type

        :param regname: string containing the registry name.
        :type regname: str.

        """
        for cls in self._bios_classes_registry:
            found = cls.find_bios_registry(regname=regname)
            if found:
                return found
        return None

    def get_errors(self):
        """Return a list of errors encountered"""
        return self._errors

    def _is_local(self, path):
        """Determine if path is a local file or remote

        :param path: The path to examine.
        :type path: str.

        """
        if u'://' in path:
            return False
        return True


class Classes(RisObject):
    """Represents an entry in the Classes registry"""
    def __init__(self, item):
        super(Classes, self).__init__(item)
        self._root = None

    def set_root(self, newroot):
        """Set new root

        :param newroot: new root to be set.
        :type newroot: str.

        """
        self._root = newroot

    def find_schema(self, schname):
        """Returns iLO schemas

        :param schname: string containing the schema name.
        :type schname: str.
        :returns: returns iLO schema

        """
        result = None

        if hasattr(self, 'Items') and isinstance(self.Items, list):
            for entry in self.Items:
                if entry and u'Schema' in entry and entry[u'Schema'].lower() \
                                                            == schname.lower():
                    regentry = RepoRegistryEntry.parse(entry)
                    regentry.set_root(self._root)
                    result = regentry
                    break
        elif hasattr(self, 'Members') and isinstance(self.Members, list):
            schname = schname.split('.')[-1]
            for entry in self.Members:
                schlink = entry[u'@odata.id'].split('/')
                schlink = schlink[len(schlink)-2]

                if schname.lower() == schlink.lower():
                    result = entry
                    break

        return result

    def find_registry(self, regname):
        """Returns iLO registries

        :param regname: string containing the registry name.
        :type regname: str.
        :returns: returns iLO registries

        """
        result = None
        if hasattr(self, 'Items') and isinstance(self.Items, list):
            for entry in self.Items:
                if entry and (u'Schema' in entry and \
                        entry[u'Schema'].lower().startswith(regname.lower())):
                    regentry = RepoRegistryEntry.parse(entry)
                    regentry.set_root(self._root)
                    result = regentry
                    break
        elif hasattr(self, 'Members') and isinstance(self.Members, list):
            regname = regname.split('.')[-1]
            for entry in self.Members:
                reglink = entry[u'@odata.id'].split('/')
                reglink = reglink[len(reglink)-2]
                if regname.lower() == reglink.lower():
                    result = entry
                    break

        return result

    def find_bios_schema(self, schname):
        """Returns BIOS schemas

        :param schname: string containing the schema name.
        :type schname: str.
        :returns: returns the BIOS schemas

        """
        result = None
        if hasattr(self, 'Items') and isinstance(self.Items, list):
            for entry in self.Items:
                if u'Schema' in entry and entry[u'Schema'].lower() == \
                                                                schname.lower():
                    regentry = RepoRegistryEntry.parse(entry)
                    regentry.set_root(self._root)
                    result = regentry
                    break
        elif hasattr(self, 'Members') and isinstance(self.Members, list):
            schname = schname.split('.')[-1]
            for entry in self.Members:
                schlink = entry[u'@odata.id'].split('/')
                schlink = schlink[len(schlink)-2]
                if schname.lower() == schlink.lower():
                    result = entry
                    break

        return result

    def find_bios_registry(self, regname):
        """Returns BIOS registries

        :param regname: string containing the registry name.
        :type regname: str.
        :returns: returns the BIOS registries

        """
        result = None
        if hasattr(self, 'Items') and isinstance(self.Items, list):
            for entry in self.Items:
                if entry and (u'Schema' in entry and regname.lower() in \
                                                    entry[u'Schema'].lower()):
                    regentry = RepoRegistryEntry.parse(entry)
                    regentry.set_root(self._root)
                    result = regentry
                    break
        elif hasattr(self, 'Members') and isinstance(self.Members, list):
            for entry in self.Members:
                reglink = entry[u'@odata.id'].split('/')
                reglink = reglink[len(reglink)-2]
                if regname.lower() == reglink.lower():
                    result = entry
                    break

        return result


class RepoBaseEntry(RisObject):
    """Represents an entry in the Classes registry"""
    def __init__(self, d):
        super(RepoBaseEntry, self).__init__(d)
        self._root = None

    def set_root(self, newroot):
        """Set new root

        :param newroot: new root to be set.
        :type newroot: str.

        """
        self._root = newroot

    def _read_location_file(self, currloc, errlist):
        """Return results from locations

        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param errlist: list containing found errors.
        :type errlist: list.

        """
        result = None
        if u'Uri' in currloc:
            root = os.path.normpath(self._root)
            xref = os.path.normpath(currloc.Uri.extref).lstrip(os.path.sep)
            fqpath = os.path.join(root, xref)

            if not os.path.isfile(fqpath):
                errlist.append(SchemaValidationError(\
                                u"Unable to location ArchiveUri '%s'" % fqpath))
            else:
                result = None
                if fqpath.endswith('.json'):
                    result = open(fqpath).read()

        return result


class RepoRegistryEntry(RepoBaseEntry):
    """Represents an entry in the Classes registry"""
    def __init__(self, d):
        super(RepoRegistryEntry, self).__init__(d)

    def validate(self, tdict, errlist=None, selector=None, currdict=None, \
                                    checkall=False, monolith=None, newarg=None):
        """Load the schema file and validate tdict against it

        :param tdict: the dictionary to test against.
        :type tdict: dict.
        :param errlist: list containing found errors.
        :type errlist: list.
        :param selector: the type selection for the get operation.
        :type selector: str.
        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param checkall: flag to determine if check all should be enabled.
        :type checkall: boolean.
        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :returns: returns an error list.

        """
        if not errlist:
            errlist = list()

        reg = self.get_registry_model(errlist=errlist, currdict=currdict, \
                                            monolith=monolith, newarg=newarg)

        if reg and not checkall:
            try:
                if reg[selector].readonly:
                    return True
            except BaseException:
                pass
            else:
                pass

            results = reg.validate_attribute_values(tdict)
            errlist.extend(results)
        elif checkall and selector is None:
            results = reg.validate_attribute_values(tdict)
            errlist.extend(results)
        else:
            errlist.append(RegistryValidationError(u'Unable to locate ' \
                                                            'registry model'))

        if errlist:
            return errlist

    def validate_bios_version(self, tdict, errlist=None, selector=None, \
                              checkall=False, currdict=None, monolith=None):
        """BIOS VERSION. Load the schema file and validate tdict against it

        :param tdict: the dictionary to test against.
        :type tdict: dict.
        :param errlist: list containing found errors.
        :type errlist: list.
        :param selector: the type selection for the get operation.
        :type selector: str.
        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param checkall: flag to determine if check all should be enabled.
        :type checkall: boolean.
        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :returns: returns an error list

        """
        if not errlist:
            errlist = list()

        reg = self.get_registry_model_bios_version(errlist=errlist, \
                                           currdict=currdict, monolith=monolith)

        if reg and not checkall:
            for item in reg.Attributes:
                if not item["Name"] == selector:
                    continue

                # validate that selector isn't read-only or a unique property
                if item["ReadOnly"] is True:
                    return 'readonly'

                try:
                    if item["IsSystemUniqueProperty"] is True:
                        return 'unique'
                except BaseException:
                    continue
                else:
                    continue

            results = reg.validate_att_val_bios(tdict)
            errlist.extend(results)
        elif checkall and selector is None:
            results = reg.validate_att_val_bios(tdict)
            errlist.extend(results)
        else:
            errlist.append(RegistryValidationError(u'Unable to locate ' \
                                                            'registry model'))

        if errlist:
            return errlist

    def validate_deprecated(self, tdict, errlist=None):
        """Load the schema file and validate tdict against it

        :param tdict: the dictionary to test against.
        :type tdict: list.
        :param errlist: list containing found errors.
        :type errlist: list.
        :returns: returns an error list

        """
        if not errlist:
            errlist = list()

        if not hasattr(self, u'Location'):
            errlist.append(RegistryValidationError(u'Location property does' \
                                                                ' not exist'))
            return errlist

        currloc = None
        defloc = None
        langcode = 'TBD'

        for loc in self.Location:
            for loclang in loc.keys():
                if loclang.lower() == langcode.lower():
                    currloc = loc[loclang]
                    break
                elif loclang.lower() == u'default':
                    defloc = loc[loclang]

        if not currloc:
            # use default location if lang doesn't match
            currloc = defloc

        if not currloc:
            errlist.append(RegistryValidationError(u'Unable to determine' \
                                                                ' location'))
            return

        location_file = self._read_location_file(currloc, errlist=errlist)
        if not location_file:
            errlist.append(RegistryValidationError(u'Location data is empty'))
        else:
            jsonreg = json.loads(location_file)
            if u'Registry' in jsonreg:
                if u'Type' in jsonreg and jsonreg[u'Type'] == \
                                            u'HpPropertiesRegistrySchema.1.0.0':
                    reg = HpPropertiesRegistry.parse(jsonreg[u'Registry'])
                    results = reg.validate_attribute_values(tdict)
                    errlist.extend(results)

    def get_registry_model(self, currdict=None, monolith=None, errlist=None, \
           skipcommit=False, searchtype=None, newarg=None, latestschema=None):
        """Load the schema file and find the registry model if available

        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        :param errlist: list containing found errors.
        :type errlist: list.
        :param skipcommit: flag to determine if commit should be skipped.
        :type skipcommit: boolean.
        :param searchtype: classifier for the current search.
        :type searchtype: str.
        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :param latestschema: flag to determine if we should use smart schema.
        :type latestschema: boolean.
        :returns: returns registry model

        """
        if not errlist:
            errlist = list()

        if not hasattr(self, u'Location'):
            errlist.append(RegistryValidationError(
                u'Location property does not exist'))
            return None

        currloc = None
        defloc = "en"
        langcode = list(locale.getdefaultlocale())

        if not langcode[0]:
            langcode[0] = "en"

        for loc in self.Location:
            locationlanguage = loc["Language"].lower()
            locationlanguage = locationlanguage.replace("-", "_")

            if locationlanguage in langcode[0].lower():
                currloc = loc
                break

        if not currloc:
            # use default location if lang doesn't match
            currloc = defloc

        if not currloc:
            errlist.append(RegistryValidationError(u'Unable to determine ' \
                                                                    'location'))
            return None

        if not searchtype:
            searchtype = "ob"

        location_file = None
        if currdict and monolith:
            for itemtype in monolith.types:
                if itemtype.lower().startswith(searchtype.lower()) and \
                                    u'Instances' in monolith.types[itemtype]:
                    for instance in monolith.types[itemtype][u'Instances']:
                        try:
                            if monolith.is_redfish and 'title' in instance.\
                                        resp.dict and not instance.resp.dict\
                                                    ["title"].startswith('#'):
                                currtype = currdict[instance._typestring].\
                                                                split('#')[-1]
                                currtype = currtype.split('.')[0] + '.'
                            else:
                                currtype = currdict[instance._typestring]

                            if latestschema:
                                if monolith.is_redfish and 'title' in instance.\
                                        resp.dict and not instance.resp.dict\
                                                    ["title"].startswith('#'):
                                    currtype = currdict[instance._typestring].\
                                                                split('#')[-1]
                                    currtype = currtype.split('.')[0]
                                else:
                                    currtype = currdict[instance._typestring].\
                                                                split('.')[0]
                                insttype = instance.resp.dict["title"].split('.')[0]

                                if currtype == insttype or currtype == \
                                                    instance.resp.dict[\
                                                   "oldtitle"].split('.')[0]:
                                    location_file = instance.resp.dict
                                    break
                            elif searchtype == "ob" and instance.resp.dict[\
                                       "title"].startswith(currtype) or \
                                       "oldtitle" in instance.resp.dict.\
                                       keys() and currdict[instance._typestring\
                                           ] == instance.resp.dict["oldtitle"]:
                                location_file = instance.resp.dict
                                break
                            elif searchtype != "ob" and \
                                    currdict[instance._typestring] \
                                    in instance.resp.dict["RegistryPrefix"]:
                                location_file = instance.resp.dict
                                break
                        except BaseException:
                            pass
                        else:
                            pass

                if location_file:
                    break
        else:
            location_file = self._read_location_file(currloc, errlist=errlist)

        if not location_file:
            errlist.append(RegistryValidationError(u'Location data is empty'))
        else:
            if currdict and monolith:
                jsonreg = json.loads(json.dumps(location_file, indent=2, \
                                                            cls=JSONEncoder))
            else:
                jsonreg = json.loads(location_file)

            if skipcommit:
                return jsonreg["Messages"]

            if u'properties' in jsonreg:
                regitem = jsonreg[u'properties']
                reg = HpPropertiesRegistry.parse(regitem)

                if newarg:
                    regcopy = reg
                    for arg in newarg[:-1]:
                        try:
                            if 'properties' in regcopy[arg].iterkeys() \
                                                and ('patternProperties' in \
                                                    regcopy[arg].iterkeys()):
                                regcopy[arg]['properties'].update(\
                                              regcopy[arg]['patternProperties'])
                                regcopy = regcopy[arg]["properties"]

                                for pattern in regcopy.iterkeys():
                                    test = re.compile(pattern)
                                    nextarg = newarg[newarg.index(arg)+1]
                                    match = test.match(nextarg)

                                    if match:
                                        regcopy[nextarg] = regcopy.pop(pattern)
                                        break
                            elif 'oneOf' in regcopy[arg]:
                                oneof = regcopy[arg]['oneOf']
                                for item in oneof:
                                    regcopy = item['properties']

                                    if not arg == newarg[-1]:
                                        try:
                                            nextitem = newarg[newarg.index(arg)+1]
                                            regcopy[nextitem]
                                            break
                                        except Exception:
                                            continue
                            else:
                                regcopy = regcopy[arg]["properties"]
                        except Exception:
                            try:
                                regcopy = regcopy[arg]['patternProperties']
                                for pattern in regcopy.iterkeys():
                                    test = re.compile(pattern)
                                    nextarg = newarg[newarg.index(arg)+1]
                                    match = test.match(nextarg)

                                    if match:
                                        patterninfo = regcopy.pop(pattern)
                                        regcopy[nextarg] = patterninfo
                            except BaseException:
                                return None

                    reg = regcopy

            return reg
        return None

    def get_registry_model_bios_version(self, currdict=None, monolith=None, \
                                                                errlist=None):
        """BIOS VERSION Load the schema file and find the registry model"""
        """ if available.

        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        :param errlist: list containing found errors.
        :type errlist: list.
        :returns: returns the registry model

        """
        attregType = Typepathforval.typepath.defs.AttributeRegType
        if not errlist:
            errlist = list()

        if not hasattr(self, u'Location'):
            errlist.append(RegistryValidationError(
                u'Location property does not exist'))
            return None

        currloc = None
        defloc = "en"
        langcode = list(locale.getdefaultlocale())

        if not langcode[0]:
            langcode[0] = "en"

        for loc in self.Location:
            locationlanguage = loc["Language"].lower()
            locationlanguage = locationlanguage.replace("-", "_")
            if locationlanguage in langcode[0].lower():
                currloc = loc
                break

        if not currloc:
            # use default location if lang doesn't match
            currloc = defloc

        if not currloc:
            errlist.append(RegistryValidationError(
                u'Unable to determine location'))
            return None

        location_file = None
        if currdict and monolith:
            for itemtype in monolith.types:
                if attregType in itemtype and \
                                    u'Instances' in monolith.types[itemtype]:
                    for instance in monolith.types[itemtype][u'Instances']:
                        location_file = instance.resp.dict
                        break

                if location_file:
                    break
        else:
            location_file = self._read_location_file(currloc, errlist=errlist)

        if not location_file:
            errlist.append(RegistryValidationError(u'Location data is empty'))
        else:
            if currdict and monolith:
                jsonreg = json.loads(json.dumps(location_file, indent=2, \
                                                            cls=JSONEncoder))
            else:
                jsonreg = json.loads(location_file)

            if u'RegistryEntries' in jsonreg:
                regitem = jsonreg[u'RegistryEntries']
                reg = HpPropertiesRegistry.parse(regitem)
                return reg

        return None


class RepoSchemaEntry(RepoBaseEntry):
    """Represents an entry in the Classes registry"""
    def __init__(self, item):
        super(RepoSchemaEntry, self).__init__(item)
        self._root = None

    def set_root(self, newroot):
        """Set new root

        :param newroot: new root to be set.
        :type newroot: str.

        """
        self._root = newroot

    def _read_location_file(self, currloc, errlist):
        """Return results from locations

        :param currloc: current URI
        :type currloc: str
        :param errlist: list containing found errors.
        :type errlist: list.
        :returns: returns results from archive at currloc parameter

        """
        if u'ArchiveUri' in currloc and u'ArchiveFile' in currloc:
            fqpath = os.path.join(self._root, \
                                  currloc.ArchiveUri.xref.lstrip(os.path.sep))
            if not os.path.isfile(fqpath):
                errlist.append(SchemaValidationError(u"Unable to location " \
                                                    "ArchiveUri '%s'" % fqpath))
            else:
                archive_file = currloc.ArchiveFile
                archive_fh = None
                result = None

                if fqpath.endswith('.zip'):
                    archive_fh = zipfile.ZipFile(fqpath)

                    infolist = archive_fh.infolist()
                    for i in infolist:
                        if i.filename.lower() == archive_file.lower():
                            jsonsch_fh = archive_fh.open(i)
                            result = jsonsch_fh.read()
                            jsonsch_fh.close()

                    archive_fh.close()

        return result

    def validate(self, tdict, errlist=None):
        """Load the schema file and validate tdict against it

        :param tdict: the dictionary to test against.
        :type tdict: list.
        :param errlist: list containing found errors.
        :type errlist: list.

        """
        if not errlist:
            errlist = list()

        result = list()
        if not hasattr(self, u'Location'):
            result.append(SchemaValidationError(u'Location property does ' \
                                                                'not exist'))
            return result

        currloc = None
        defloc = None
        langcode = 'TBD'
        for loc in self.Location:
            for loclang in loc.keys():
                if loclang.lower() == langcode.lower():
                    currloc = loc[loclang]
                    break
                elif loclang.lower() == u'default':
                    defloc = loc[loclang]

        if not currloc:
            # use default location if lang doesn't match
            currloc = defloc

        if not currloc:
            result.append(SchemaValidationError(
                u'Unable to determine location'))
            return

        location_file = self._read_location_file(currloc, errlist=result)
        if not location_file:
            result.append(SchemaValidationError(u'Location data is empty'))
        else:
            jsonsch = json.loads(location_file)
            validictory.validate(tdict, jsonsch)


class HpPropertiesRegistry(RisObject):
    """Models the HpPropertiesRegistry file"""
    def __init__(self, d):
        super(HpPropertiesRegistry, self).__init__(d)

    def validate_attribute_values(self, tdict):
        """Look for tdict in attribute list and attempt to validate its value

        :param tdict: the dictionary to test against.
        :type tdict: list.
        :returns: returns a validated list

        """
        result = list()

        for tkey in tdict:
            try:
                if self[tkey] and hasattr(self[tkey], "type"):
                    keyval = list()
                    keyval.append(tdict[tkey])
                    temp = self.validate_attribute(self[tkey], keyval, tkey)
                    tdict[tkey] = keyval[0]

                    for err in temp:
                        if isinstance(err, RegistryValidationError):
                            if err.reg:
                                err.sel = tkey

                    result.extend(temp)
            except Exception:
                pass

        return result

    def validate_att_val_bios(self, tdict):
        """Look for tdict in attribute list and attempt to validate its value

        :param tdict: the dictionary to test against.
        :type tdict: list.
        :returns: returns a validated list

        """
        result = list()

        for tkey in tdict:
            for item in self.Attributes:
                try:
                    if item["Name"] == tkey and hasattr(item, "Type"):
                        keyval = list()
                        keyval.append(tdict[tkey])
                        temp = self.validate_attribute(item, keyval, tkey)
                        tdict[tkey] = keyval[0]

                        for err in temp:
                            if isinstance(err, RegistryValidationError):
                                if err.reg:
                                    err.sel = tkey

                        result.extend(temp)
                        break
                except Exception:
                    pass

        return result

    def get_validator(self, attrname, newargs=None, oneof=None):
        """Returns attribute validator type

        :param attrname: attribute name to be used for validation.
        :type attrname: str.
        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :param oneof: special string for "oneof" options within validation.
        :type oneof: list.
        :returns: returns attribute validator type

        """
        if oneof:
            self = oneof

        if newargs:
            for arg in newargs:
                try:
                    self = self['properties']
                except Exception:
                    pass

                if not hasattr(self, arg):
                    return None
                elif not arg == newargs[-1]:
                    self = self[arg]

        if not hasattr(self, attrname):
            return None

        validator = None
        if EnumValidator.is_type(self[attrname]):
            validator = EnumValidator.parse(self[attrname])
        elif StringValidator.is_type(self[attrname]):
            validator = StringValidator.parse(self[attrname])
        elif ObjectValidator.is_type(self[attrname]):
            validator = ObjectValidator.parse(self[attrname])
        elif IntegerValidator.is_type(self[attrname]):
            validator = IntegerValidator.parse(self[attrname])
        elif BoolValidator.is_type(self[attrname]):
            validator = BoolValidator.parse(self[attrname])
        elif PasswordValidator.is_type(self[attrname]):
            validator = PasswordValidator.parse(self[attrname])
        elif u'oneOf' in self[attrname].keys():
            for item in self[attrname]['oneOf']:
                validator = self.get_validator(attrname, newargs, \
                                        HpPropertiesRegistry({attrname:item}))
                if validator:
                    break
        return validator

    def get_validator_bios(self, attrname):
        """Returns attribute validator type

        :param attrname: attribute name to be used for validation.
        :type attrname: str.
        :returns: returns attribute validator type

        """


        for item in self.Attributes:
            name = Typepathforval.typepath.defs.AttributeNameType
            if name not in item.keys():
                return None
            if item[name] == attrname:
                validator = None
                if EnumValidator.is_type(item):
                    validator = EnumValidator.parse(item)
                elif StringValidator.is_type(item):
                    validator = StringValidator.parse(item)
                elif IntegerValidator.is_type(item):
                    validator = IntegerValidator.parse(item)
                elif BoolValidator.is_type(item):
                    validator = BoolValidator.parse(item)
                elif ObjectValidator.is_type(item):
                    validator = ObjectValidator.parse(item)
                elif PasswordValidator.is_type(item):
                    validator = PasswordValidator.parse(item)

                return validator

        return None

    def validate_attribute(self, attrentry, attrvallist, name):
        """Function to validate attribute against iLO schema

        :param attrentry: attribute entry to be used for validation.
        :type attrentry: str.
        :param attrval: attribute value to be used for validation.
        :type attrval: str.
        :param name: clean name for outputting.
        :type name: str.
        :returns: returns list with validated attribute

        """
        result = list()
        validator = None
        attrval = attrvallist[0]

        if EnumValidator.is_type(attrentry):
            validator = EnumValidator.parse(attrentry)
            attrval = attrvallist
        elif StringValidator.is_type(attrentry):
            validator = StringValidator.parse(attrentry)
        elif IntegerValidator.is_type(attrentry):
            validator = IntegerValidator.parse(attrentry)
        elif BoolValidator.is_type(attrentry):
            validator = BoolValidator.parse(attrentry)
        elif ObjectValidator.is_type(attrentry):
            validator = ObjectValidator.parse(attrentry)
        elif PasswordValidator.is_type(attrentry):
            validator = PasswordValidator.parse(attrentry)
        else:
            raise UnknownValidatorError(attrentry)

        if validator:
            result.extend(validator.validate(attrval, name))
        return result


class BaseValidator(RisObject):
    """Base validator class"""
    def __init__(self, d):
        super(BaseValidator, self).__init__(d)

    def validate(self):
        """Overridable function for validation """
        raise RuntimeError(u'You must override this method in your derived ' \
                                                                        'class')


class EnumValidator(BaseValidator):
    """Enum validator class"""
    def __init__(self, d):
        super(EnumValidator, self).__init__(d)

    @staticmethod
    def is_type(attrentry):
        """Validate that the type is enumeration

        :param attrname: attribute name to be used for validation.
        :type attrname: str.
        :returns: returns a boolean based on whether type is eneumeration

        """
        if u'type' in attrentry:
            if isinstance(attrentry[u'type'], list):
                for item in attrentry[u'type']:
                    if item.lower() == u'enumeration':
                        return True
                    elif u'enum' in attrentry and item.lower() == u'string':
                        return True
            elif u'enum' in attrentry and attrentry[u'type'] == "array":
                for key, value in attrentry[u'items'].iteritems():
                    if key.lower() == "type" and value.lower() == u'string':
                        return True
            else:
                if attrentry[u'type'].lower() == u'enumeration':
                    return True
                elif u'enum' in attrentry and attrentry[u'type'].lower() == \
                                                                    u'string':
                    return True
        elif u'Type' in attrentry:
            if attrentry[u'Type'].lower() == u'enumeration':
                return True

        return False

    def validate(self, keyval, name):
        """Validate against iLO schema

        :param newval: new value to be used for validation.
        :type newval: str.
        :param name: clean name for outputting.
        :type name: str.
        :returns: returns an error if fails

        """
        result = list()
        newval = keyval[0]

        try:
            for possibleval in self.enum:
                if possibleval.lower() == newval.lower():
                    keyval[0] = possibleval
                    return result
        except Exception:
            for possibleval in self.Value:
                if possibleval.ValueName.lower() == str(newval).lower():
                    keyval[0] = possibleval.ValueName
                    return result

        result.append(RegistryValidationError(u"'%s' is not a valid setting " \
                                  "for '%s'" % (newval, name), regentry=self))

        return result

    def print_help(self, name, out=sys.stdout):
        """Info command helper function for print outs

        :param name: clean name for outputting.
        :type name: str.
        :param out: output type for verbosity.
        :type out: output type.

        """
        wrapper = textwrap.TextWrapper()
        wrapper.initial_indent = ' ' * 4
        wrapper.subsequent_indent = ' ' * 4

        out.write(u'\nNAME\n')
        out.write('%s' % wrapper.fill('%s' % name))
        out.write('\n')

        if u'DisplayName' in self:
            out.write(u'\nDISPLAY NAME\n')
            out.write('%s' % wrapper.fill('%(DisplayName)s' % self))
            out.write('\n')

        if u'description' in self:
            out.write(u'\nDESCRIPTION\n')
            out.write('%s' % wrapper.fill('%(description)s' % self))
            out.write('\n')

        if u'HelpText' in self:
            out.write(u'\nHELP TEXT\n')
            out.write('%s' % wrapper.fill('%(HelpText)s' % self))
            out.write('\n')

        if u'WarningText' in self:
            out.write(u'\n************************************************\n')
            out.write(u'\nWARNING\n')
            out.write('%s' % wrapper.fill('%(WarningText)s' % self))
            out.write(u'\n\n**********************************************\n')
            out.write('\n')

        if u'type' in self and isinstance(self[u'type'], list):
            out.write(u'\nTYPE\n')
            for item in self[u'type']:
                out.write('%s\n' % wrapper.fill('%s' % item))
            out.write('\n')
        elif u'type' in self:
            out.write(u'\nTYPE\n')
            out.write('%s' % wrapper.fill('%(type)s' % self))
            out.write('\n')
        elif u'Type' in self:
            out.write(u'\nTYPE\n')
            out.write('%s' % wrapper.fill('%(Type)s' % self))
            out.write('\n')

        if u'ReadOnly' in self:
            out.write(u'\nREAD-ONLY\n')
            out.write('%s' % wrapper.fill('%(ReadOnly)s' % self))
            out.write('\n')
        elif u'readonly' in self:
            out.write(u'\nREAD-ONLY\n')
            out.write('%s' % wrapper.fill('%(readonly)s' % self))
            out.write('\n')

        out.write(u'\nPOSSIBLE VALUES\n')
        try:
            for possibleval in self.enum:
                out.write('    %s\n' % possibleval)
        except Exception:
            for possibleval in self.Value:
                out.write('    %(ValueName)s\n' % possibleval)
        out.write('\n')


class BoolValidator(BaseValidator):
    """Bool validator class"""
    def __init__(self, d):
        super(BoolValidator, self).__init__(d)

    @staticmethod
    def is_type(attrentry):
        """Validate that the type is boolean

        :param attrentry: attribute entry containing data to be validated.
        :type attrentry: str.
        :returns: returns boolean on whether type is boolean

        """
        if u'type' in attrentry:
            if isinstance(attrentry[u'type'], list):
                for item in attrentry[u'type']:
                    if item.lower() == u'boolean':
                        return True
            elif attrentry[u'type'] == "array":
                for key, value in attrentry[u'items'].iteritems():
                    if key.lower() == "type" and value.lower() == u'boolean':
                        return True
            else:
                if attrentry[u'type'].lower() == u'boolean':
                    return True
        elif u'Type' in attrentry:
            if attrentry[u'Type'].lower() == u'boolean':
                return True

        return False

    def validate(self, newval, name):
        """Validate against iLO schema

        :param newval: new value to be used for validation.
        :type newval: str.
        :param name: clean name for outputting.
        :type name: str.
        :returns: returns an error if no validation value

        """
        result = list()
        if newval is False or newval is True:
            return result

        result.append(
            RegistryValidationError(u"'%s' is not a valid setting for '%s'" % \
                                                (newval, name), regentry=self))

        return result

    def print_help(self, name, out=sys.stdout):
        """Info command helper function for print outs

        :param name: clean name for outputting.
        :type name: str.
        :param out: output type for verbosity.
        :type out: output type.

        """
        wrapper = textwrap.TextWrapper()
        wrapper.initial_indent = ' ' * 4
        wrapper.subsequent_indent = ' ' * 4

        out.write(u'\nNAME\n')
        out.write('%s' % wrapper.fill('%s' % name))
        out.write('\n')

        if u'DisplayName' in self:
            out.write(u'\nDISPLAY NAME\n')
            out.write('%s' % wrapper.fill('%(DisplayName)s' % self))
            out.write('\n')

        if u'description' in self:
            out.write(u'\nDESCRIPTION\n')
            out.write('%s' % wrapper.fill('%(description)s' % self))
            out.write('\n')

        if u'HelpText' in self:
            out.write(u'\nHELP TEXT\n')
            out.write('%s' % wrapper.fill('%(HelpText)s' % self))
            out.write('\n')

        if u'WarningText' in self:
            out.write(u'\n************************************************\n')
            out.write(u'\nWARNING\n')
            out.write('%s' % wrapper.fill('%(WarningText)s' % self))
            out.write(u'\n\n**********************************************\n')
            out.write('\n')

        if u'type' in self and isinstance(self[u'type'], list):
            out.write(u'\nTYPE\n')
            for item in self[u'type']:
                out.write('%s\n' % wrapper.fill('%s' % item))
            out.write('\n')
        elif u'type' in self:
            out.write(u'\nTYPE\n')
            out.write('%s' % wrapper.fill('%(type)s' % self))
            out.write('\n')
        elif u'Type' in self:
            out.write(u'\nTYPE\n')
            out.write('%s' % wrapper.fill('%(Type)s' % self))
            out.write('\n')

        if u'ReadOnly' in self:
            out.write(u'\nREAD-ONLY\n')
            out.write('%s' % wrapper.fill('%(ReadOnly)s' % self))
            out.write('\n')
        elif u'readonly' in self:
            out.write(u'\nREAD-ONLY\n')
            out.write('%s' % wrapper.fill('%(readonly)s' % self))
            out.write('\n')

        out.write(u'\nPOSSIBLE VALUES\n')
        out.write('    True or False\n')
        out.write('\n')


class StringValidator(BaseValidator):
    """Constructor """
    def __init__(self, d):
        super(StringValidator, self).__init__(d)

    @staticmethod
    def is_type(attrentry):
        """Validate that the type is string

        :param attrentry: attribute entry containing data to be validated.
        :type attrentry: str.
        :returns: returns boolean based on whether type to validate is string

        """
        if u'type' in attrentry:
            if isinstance(attrentry[u'type'], list):
                for item in attrentry[u'type']:
                    if item.lower() == u'string':
                        return True
            elif attrentry[u'type'] == "array":
                for key, value in attrentry[u'items'].iteritems():
                    if key.lower() == "type" and u'string' in value:
                        return True
            else:
                if attrentry[u'type'].lower() == u'string':
                    return True
        elif u'Type' in attrentry:
            if attrentry[u'Type'].lower() == u'string':
                return True

        return False

    def validate(self, newval, _):
        """Validate against iLO schema

        :param newval: new value to be used for validation.
        :type newval: str.
        :returns: returns an error if validation fails criteria

        """
        result = list()
        if u'MinLength' in self:
            if len(newval) < int(self[u'MinLength']):
                result.append(RegistryValidationError(
                    u"'%s' must be at least '%s' characters long" %
                    (self.Name, int(self[u'MinLength'])), regentry=self))

        if u'MaxLength' in self:
            if len(newval) > int(self[u'MaxLength']):
                result.append(RegistryValidationError(
                    u"'%s' must be less than '%s' characters long" %
                    (self.Name, int(self[u'MaxLength'])), regentry=self))

        if u'ValueExpression' in self:
            if self[u'ValueExpression']:
                pat = re.compile(self[u'ValueExpression'])
                if newval and not pat.match(newval):
                    result.append(RegistryValidationError(
                        u"'%(Name)s' must match the regular expression "
                        "'%(ValueExpression)s'" % (self), regentry=self))

        return result

    def print_help(self, name, out=sys.stdout):
        """Info command helper function for print outs

        :param name: clean name for outputting.
        :type name: str.
        :param out: output type for verbosity.
        :type out: output type.

        """
        wrapper = textwrap.TextWrapper()
        wrapper.initial_indent = ' ' * 4
        wrapper.subsequent_indent = ' ' * 4

        out.write(u'\nNAME\n')
        out.write('%s' % wrapper.fill('%s' % name))
        out.write('\n')

        if u'DisplayName' in self:
            out.write(u'\nDISPLAY NAME\n')
            out.write('%s' % wrapper.fill('%(DisplayName)s' % self))
            out.write('\n')

        if u'description' in self:
            out.write(u'\nDESCRIPTION\n')
            out.write('%s' % wrapper.fill('%(description)s' % self))
            out.write('\n')

        if u'HelpText' in self:
            out.write(u'\nHELP TEXT\n')
            out.write('%s' % wrapper.fill('%(HelpText)s' % self))
            out.write('\n')

        if u'WarningText' in self:
            out.write(u'\n************************************************\n')
            out.write(u'\nWARNING\n')
            out.write('%s' % wrapper.fill('%(WarningText)s' % self))
            out.write(u'\n\n**********************************************\n')
            out.write('\n')

        if u'type' in self and isinstance(self[u'type'], list):
            out.write(u'\nTYPE\n')
            for item in self[u'type']:
                out.write('%s\n' % wrapper.fill('%s' % item))
            out.write('\n')
        elif u'type' in self:
            out.write(u'\nTYPE\n')
            out.write('%s' % wrapper.fill('%(type)s' % self))
            out.write('\n')
        elif u'Type' in self:
            out.write(u'\nTYPE\n')
            out.write('%s' % wrapper.fill('%(Type)s' % self))
            out.write('\n')

        if u'MinLength' in self:
            out.write(u'\nMIN LENGTH\n')
            out.write('%s' % wrapper.fill('%(MinLength)s' % self))
            out.write('\n')

        if u'MaxLength' in self:
            out.write(u'\nMAX LENGTH\n')
            out.write('%s' % wrapper.fill('%(MaxLength)s' % self))
            out.write('\n')

        if u'ReadOnly' in self:
            out.write(u'\nREAD-ONLY\n')
            out.write('%s' % wrapper.fill('%(ReadOnly)s' % self))
            out.write('\n')
        elif u'readonly' in self:
            out.write(u'\nREAD-ONLY\n')
            out.write('%s' % wrapper.fill('%(readonly)s' % self))
            out.write('\n')


class IntegerValidator(BaseValidator):
    """Interger validator class"""
    def __init__(self, d):
        super(IntegerValidator, self).__init__(d)

    @staticmethod
    def is_type(attrentry):
        """Validate that the type is integer

        :param attrname: attribute name to be used for validation.
        :type attrname: str.
        :returns: returns boolean based on type being an integer

        """
        if u'type' in attrentry:
            if isinstance(attrentry[u'type'], list):
                for item in attrentry[u'type']:
                    if item.lower() == u'integer' or item.lower() == u'number':
                        return True
            elif attrentry[u'type'] == "array":
                for key, value in attrentry[u'items'].iteritems():
                    if key.lower() == "type":
                        if value.lower() == u'interger' or value.lower() == \
                                                                    u'number':
                            return True
            else:
                if attrentry[u'type'].lower() == u'integer' or \
                            attrentry[u'type'].lower().lower() == u'number':
                    return True
        elif u'Type' in attrentry:
            if attrentry[u'Type'].lower() == u'integer':
                return True

        return False

    def validate(self, newval, _):
        """Validate against iLO schema

        :param newval: new value to be used for validation.
        :type newval: str.

        """
        result = list()
        intval = int(newval)

        pat = re.compile(r'0-9+')
        if newval and not pat.match(intval):
            result.append(
                RegistryValidationError(
                    u"'%(Name)s' must be an integer value'" % (self),
                    regentry=self
                )
            )
            return result

        if u'LowerBound' in self:
            if intval < int(self[u'LowerBound']):
                result.append(RegistryValidationError(u"'%s' must be greater" \
                                      " than or equal to '%s'" % (self.Name, \
                                      int(self[u'LowerBound'])), regentry=self))

        if u'UpperBound' in self:
            if intval > int(self[u'UpperBound']):
                result.append(RegistryValidationError(u"'%s' must be less " \
                                      "than or equal to '%s'" % (self.Name, \
                                     int(self[u'LowerBound'])), regentry=self))

        return result

    def print_help(self, name, out=sys.stdout):
        """Info command helper function for print outs

        :param name: clean name for outputting.
        :type name: str.
        :param out: output type for verbosity.
        :type out: output type.

        """
        wrapper = textwrap.TextWrapper()
        wrapper.initial_indent = ' ' * 4
        wrapper.subsequent_indent = ' ' * 4

        out.write(u'\nNAME\n')
        out.write('%s' % wrapper.fill('%s' % name))
        out.write('\n')

        if u'DisplayName' in self:
            out.write(u'\nDISPLAY NAME\n')
            out.write('%s' % wrapper.fill('%(DisplayName)s' % self))
            out.write('\n')

        if u'description' in self:
            out.write(u'\nDESCRIPTION\n')
            out.write('%s' % wrapper.fill('%(description)s' % self))
            out.write('\n')

        if u'HelpText' in self:
            out.write(u'\nHELP TEXT\n')
            out.write('%s' % wrapper.fill('%(HelpText)s' % self))
            out.write('\n')

        if u'WarningText' in self:
            out.write(u'\n************************************************\n')
            out.write(u'\nWARNING\n')
            out.write('%s' % wrapper.fill('%(WarningText)s' % self))
            out.write(u'\n\n**********************************************\n')
            out.write('\n')

        if u'type' in self and isinstance(self[u'type'], list):
            out.write(u'\nTYPE\n')
            for item in self[u'type']:
                out.write('%s\n' % wrapper.fill('%s' % item))
            out.write('\n')
        elif u'type' in self:
            out.write(u'\nTYPE\n')
            out.write('%s' % wrapper.fill('%(type)s' % self))
            out.write('\n')
        elif u'Type' in self:
            out.write(u'\nTYPE\n')
            out.write('%s' % wrapper.fill('%(Type)s' % self))
            out.write('\n')

        if u'ReadOnly' in self:
            out.write(u'\nREAD-ONLY\n')
            out.write('%s' % wrapper.fill('%(ReadOnly)s' % self))
            out.write('\n')
        elif u'readonly' in self:
            out.write(u'\nREAD-ONLY\n')
            out.write('%s' % wrapper.fill('%(readonly)s' % self))
            out.write('\n')


class ObjectValidator(BaseValidator):
    """Object validator class"""
    def __init__(self, d):
        super(ObjectValidator, self).__init__(d)

    @staticmethod
    def is_type(attrentry):
        """Validate that the type is object

        :param attrname: attribute name to be used for validation.
        :type attrname: str.
        :returns: returns boolean based on whether type is an object

        """
        if u'type' in attrentry:
            if isinstance(attrentry[u'type'], list):
                for item in attrentry[u'type']:
                    if item.lower() == u'object':
                        return True
            elif attrentry[u'type'] == "array":
                for key, value in attrentry[u'items'].iteritems():
                    if key.lower() == "type" and value.lower() == u'object':
                        return True
                    elif key.lower() == "anyof":
                        try:
                            if value[0][u'type'] == u'object':
                                return True
                        except Exception:
                            continue
            else:
                if attrentry[u'type'].lower() == u'object':
                    return True
        elif u'Type' in attrentry:
            if attrentry[u'Type'].lower() == u'object':
                return True

        return False

    def validate(self, _, __):
        """Validate against iLO schema

        :param newval: new value to be used for validation.
        :type newval: str.

        """
        #TODO need to add so logic for objects class?
        result = list()
        return result

    def print_help(self, name, out=sys.stdout):
        """Info command helper function for print outs

        :param name: clean name for outputting.
        :type name: str.
        :param out: output type for verbosity.
        :type out: output type.

        """
        wrapper = textwrap.TextWrapper()
        wrapper.initial_indent = ' ' * 4
        wrapper.subsequent_indent = ' ' * 4

        out.write(u'\nNAME\n')
        out.write('%s' % wrapper.fill('%s' % name))
        out.write('\n')

        if u'DisplayName' in self:
            out.write(u'\nDISPLAY NAME\n')
            out.write('%s' % wrapper.fill('%(DisplayName)s' % self))
            out.write('\n')

        if u'description' in self:
            out.write(u'\nDESCRIPTION\n')
            out.write('%s' % wrapper.fill('%(description)s' % self))
            out.write('\n')

        if u'HelpText' in self:
            out.write(u'\nHELP TEXT\n')
            out.write('%s' % wrapper.fill('%(HelpText)s' % self))
            out.write('\n')

        if u'WarningText' in self:
            out.write(u'\n************************************************\n')
            out.write(u'\nWARNING\n')
            out.write('%s' % wrapper.fill('%(WarningText)s' % self))
            out.write(u'\n\n**********************************************\n')
            out.write('\n')

        if u'type' in self and isinstance(self[u'type'], list):
            out.write(u'\nTYPE\n')
            for item in self[u'type']:
                out.write('%s\n' % wrapper.fill('%s' % item))
            out.write('\n')
        elif u'type' in self:
            out.write(u'\nTYPE\n')
            out.write('%s' % wrapper.fill('%(type)s' % self))
            out.write('\n')
        elif u'Type' in self:
            out.write(u'\nTYPE\n')
            out.write('%s' % wrapper.fill('%(Type)s' % self))
            out.write('\n')

        if u'ReadOnly' in self:
            out.write(u'\nREAD-ONLY\n')
            out.write('%s' % wrapper.fill('%(ReadOnly)s' % self))
            out.write('\n')
        elif u'readonly' in self:
            out.write(u'\nREAD-ONLY\n')
            out.write('%s' % wrapper.fill('%(readonly)s' % self))
            out.write('\n')


class PasswordValidator(BaseValidator):
    """Password validator class"""
    def __init__(self, d):
        super(PasswordValidator, self).__init__(d)

    @staticmethod
    def is_type(attrentry):
        """Validate that the type is password

        :param attrname: attribute name to be used for validation.
        :type attrname: str.
        :returns: returns boolean whether type is password

        """
        if u'type' in attrentry:
            if isinstance(attrentry[u'type'], list):
                for item in attrentry[u'type']:
                    if item.lower() == u'password':
                        return True
            elif attrentry[u'type'] == "array":
                for key, value in attrentry[u'items'].iteritems():
                    if key.lower() == "type" and value.lower() == u'password':
                        return True
            else:
                if attrentry[u'type'].lower() == u'password':
                    return True
        elif u'Type' in attrentry:
            if attrentry[u'Type'].lower() == u'password':
                return True

        return False

    def validate(self, newval, _):
        """Validate against iLO schema

        :param newval: new value to be used for validation.
        :type newval: str.
        :returns: returns an validation error if criteria not met

        """
        result = list()

        if newval is None:
            return result

        if u'MinLength' in self:
            if len(newval) < int(self[u'MinLength']):
                result.append(RegistryValidationError(u"'%s' must be at least" \
                                      " '%s' characters long" % (self.Name, \
                                     int(self[u'MinLength'])), regentry=self))

        if u'MaxLength' in self:
            if len(newval) > int(self[u'MaxLength']):
                result.append(RegistryValidationError(u"'%s' must be less " \
                                  "than '%s' characters long" % (self.Name, \
                                     int(self[u'MaxLength'])), regentry=self))

        if u'ValueExpression' in self:
            if self[u'ValueExpression']:
                pat = re.compile(self[u'ValueExpression'])
                if newval and not pat.match(newval):
                    result.append(RegistryValidationError(u"'%(Name)s' must " \
                                      "match the regular expression '%(Value" \
                                      "Expression)s'" % (self), regentry=self))

        return result

    def print_help(self, name, out=sys.stdout):
        """Info command helper function for print outs

        :param name: clean name for outputting.
        :type name: str.
        :param out: output type for verbosity.
        :type out: output type.

        """
        wrapper = textwrap.TextWrapper()
        wrapper.initial_indent = ' ' * 4
        wrapper.subsequent_indent = ' ' * 4

        out.write(u'\nNAME\n')
        out.write('%s' % wrapper.fill('%s' % name))
        out.write('\n')

        if u'DisplayName' in self:
            out.write(u'\nDISPLAY NAME\n')
            out.write('%s' % wrapper.fill('%(DisplayName)s' % self))
            out.write('\n')

        if u'description' in self:
            out.write(u'\nDESCRIPTION\n')
            out.write('%s' % wrapper.fill('%(description)s' % self))
            out.write('\n')

        if u'HelpText' in self:
            out.write(u'\nHELP TEXT\n')
            out.write('%s' % wrapper.fill('%(HelpText)s' % self))
            out.write('\n')

        if u'WarningText' in self:
            out.write(u'\n************************************************\n')
            out.write(u'\nWARNING\n')
            out.write('%s' % wrapper.fill('%(WarningText)s' % self))
            out.write(u'\n\n**********************************************\n')
            out.write('\n')

        if u'type' in self and isinstance(self[u'type'], list):
            out.write(u'\nTYPE\n')
            for item in self[u'type']:
                out.write('%s\n' % wrapper.fill('%s' % item))
            out.write('\n')
        elif u'type' in self:
            out.write(u'\nTYPE\n')
            out.write('%s' % wrapper.fill('%(type)s' % self))
            out.write('\n')
        elif u'Type' in self:
            out.write(u'\nTYPE\n')
            out.write('%s' % wrapper.fill('%(Type)s' % self))
            out.write('\n')

        if u'MinLength' in self:
            out.write(u'\nMIN LENGTH\n')
            out.write('%s' % wrapper.fill('%(MinLength)s' % self))
            out.write('\n')

        if u'MaxLength' in self:
            out.write(u'\nMAX LENGTH\n')
            out.write('%s' % wrapper.fill('%(MaxLength)s' % self))
            out.write('\n')

        if u'ReadOnly' in self:
            out.write(u'\nREAD-ONLY\n')
            out.write('%s' % wrapper.fill('%(ReadOnly)s' % self))
            out.write('\n')
        elif u'readonly' in self:
            out.write(u'\nREAD-ONLY\n')
            out.write('%s' % wrapper.fill('%(readonly)s' % self))
            out.write('\n')

class Typepathforval(object):
    """Way to store the typepath defines object."""
    typepath = None
    def __new__(cls, typepathobj):
        if typepathobj:
            Typepathforval.typepath = typepathobj
        pass

