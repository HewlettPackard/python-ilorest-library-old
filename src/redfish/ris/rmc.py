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
"""RMC implementation """

#---------Imports---------
import os
import re
import sys
import time
import copy
import shutil
import logging
from collections import OrderedDict, Mapping

import jsonpatch
import jsonpath_rw
import jsonpointer
import redfish.ris.tpdefs
import redfish.ris.validation

from redfish.ris.ris import SessionExpiredRis
from redfish.ris.validation import ValidationManager, RepoRegistryEntry,\
                                                        Typepathforval
from redfish.ris.rmc_helper import (UndefinedClientError, InstanceNotFoundError, \
                          CurrentlyLoggedInError, NothingSelectedError, \
                          InvalidSelectionError, IdTokenError, \
                          SessionExpired, ValidationError, \
                          RmcClient, RmcConfig, RmcFileCacheManager, \
                          NothingSelectedSetError, LoadSkipSettingError, \
                          InvalidCommandLineError, FailureDuringCommitError, \
                          InvalidPathError, ValueChangedError, IloResponseError, \
                          UserNotAdminError)

#---------End of imports---------

#---------Debug logger---------

LOGGER = logging.getLogger(__name__)

#---------End of debug logger---------

class RmcApp(object):
    """Application level implementation of RMC"""
    def __init__(self, Args=None):
        """Initialize RmcApp

        :param Args: arguments to be passed to RmcApp
        :type Args: str

        """
        self._rmc_clients = []
        configfile = None

        foundsomething = False
        for item in Args:
            if foundsomething:
                configfile = item
                break

            if item == "-c":
                foundsomething = True
            elif item.startswith("--config="):
                configfile = item.split("=", 1)[1]
                break
            elif item == "--config":
                foundsomething = True

        # use the default config file
        if configfile is None:
            if os.name == 'nt':
                configfile = os.path.join(os.path.dirname(sys.executable), \
                                                                 'redfish.conf')
            else:
                configfile = '/etc/ilorest/redfish.conf'

        if not os.path.isfile(configfile):
            self.warn("Config file '%s' not found\n\n" % configfile)

        self._config = RmcConfig()
        self.config_file = configfile
        self.logger = logging.getLogger()
        self._cm = RmcFileCacheManager(self)
        self._monolith = None
        self._validationmanager = None
        self._iloversion = None

        if not "--showwarnings" in Args:
            self.logger.setLevel(logging.WARNING)
            if self.logger.handlers and self.logger.handlers[0].name == 'lerr':
                self.logger.handlers.remove(self.logger.handlers[0])

        self.typepath = redfish.ris.tpdefs.Typesandpathdefines()
        Typepathforval(typepathobj=self.typepath)

    def restore(self):
        """Restore monolith from cache"""
        self._cm.uncache_rmc()

    def deletelogoutfunction(self, url=None):
        """Wrapper function for logout helper function

        :param url: The URL to perform a logout request on.
        :type url: str.

        """
        return self._cm.logout_del_function(url)

    def save(self):
        """Cache current monolith build"""
        self._cm.cache_rmc()

    def out(self):
        """Helper function for runtime error"""
        raise RuntimeError("You must override this method in your derived" \
                                                                    " class")

    def err(self, msg, inner_except=None):
        """Helper function for runtime error

        :param msg: The error message.
        :type msg: str.
        :param inner_except: The internal exception.
        :type inner_except: str.

        """
        LOGGER.error(msg)
        if inner_except is not None:
            LOGGER.error(inner_except)

    def warning_handler(self, msg):
        """Helper function for handling warning messages appropriately

        :param msg: The warning message.
        :type msg: str.

        """
        if LOGGER.getEffectiveLevel() == 40:
            sys.stderr.write(msg)
        else:
            LOGGER.warning(msg)

    def warn(self, msg, inner_except=None):
        """Helper function for runtime warning

        :param msg: The warning message.
        :type msg: str.
        :param inner_except: The internal exception.
        :type inner_except: str.

        """
        LOGGER.warn(msg)
        if inner_except is not None:
            LOGGER.warn(inner_except)

    def get_config(self):
        """Return config"""
        return self._config

    config = property(get_config, None)

    def get_cache(self):
        """Return config"""
        return self._config

    config = property(get_cache, None)

    def config_from_file(self, filename):
        """Get config from file

        :param filename: The config file name.
        :type filename: str.

        """
        self._config = RmcConfig(filename=filename)
        self._config.load()

    def add_rmc_client(self, client):
        """Add new RMC client

        :param client: The client to be added.
        :type client: str.

        """
        for i in range(0, len(self._rmc_clients)):
            if client.get_base_url() == self._rmc_clients[i].get_base_url():
                self._rmc_clients[i] = client
                return

        # not found so add it
        self._rmc_clients.append(client)

    def remove_rmc_client(self, url=None):
        """Remove RMC client

        :param url: The URL to perform the removal to.
        :type url: str.

        """
        if url:
            for i in range(0, len(self._rmc_clients)):
                if url in self._rmc_clients[i].get_base_url():
                    del self._rmc_clients[i]
        else:
            if self._rmc_clients and len(self._rmc_clients) > 0:
                self._rmc_clients = self._rmc_clients[:-1]

    def get_rmc_client(self, url):
        """Return rmc_client with the provided URL.

        :param url: The URL of the client you are searching for.
        :type url: str.

        """
        for i in range(0, len(self._rmc_clients)):
            if url == self._rmc_clients[i].get_base_url():
                return self._rmc_clients[i]

        return None

    def check_current_rmc_client(self, url):
        """Return if RMC client already exists

        :param url: The URL to perform a check on.
        :type url: str.

        """
        if not len(self._rmc_clients):
            return True

        for i in range(0, len(self._rmc_clients)):
            if url == self._rmc_clients[i].get_base_url():
                return True

        return False

    def update_rmc_client(self, url, **kwargs):
        """Do update to passed client

        :param url: The URL for the update request.
        :type url: str.

        """
        for i in range(0, len(self._rmc_clients)):
            if url == self._rmc_clients[i].get_base_url():
                if 'username' in kwargs:
                    self._rmc_clients[i].set_username(kwargs['username'])

                if 'password' in kwargs:
                    self._rmc_clients[i].set_password(kwargs['password'])

                if 'biospassword' in kwargs:
                    self._rmc_clients[i].set_bios_password(\
                                                        kwargs['biospassword'])

    def get_current_client(self):
        """Get the current client"""
        if len(self._rmc_clients) > 0:
            return self._rmc_clients[-1]

        raise UndefinedClientError()

    current_client = property(get_current_client, None)

    def login(self, username=None, password=None, base_url=u'blobstore://.', \
              verbose=False, path=None, skipbuild=False, includelogs=False, \
              biospassword=None, is_redfish=False):
        """Main worker function for login command

        :param username: user name required to login to server.
        :type: str.
        :param password: password credentials required to login.
        :type password: str.
        :param base_url: redfish host name or ip address.
        :type base_url: str.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param path: path to initiate login to.
        :type path: str.
        :param skipbuild: flag to determine whether to start monolith download.
        :type skipbuild: boolean.
        :param includelogs: flag to determine id logs should be downloaded.
        :type includelogs: boolean.
        :param biospassword: BIOS password for the server if set.
        :type biospassword: str.
        :param is_redfish: If True, a Redfish specific header (OData) will be
            added to every request.
        :type is_redfish: boolean.

        """
        if not self.check_current_rmc_client(url=base_url):
            raise CurrentlyLoggedInError("Currently logged into another " \
                                         "server. \nPlease log out out first " \
                                         "before logging in to another.")

        existing_client = self.get_rmc_client(url=base_url)
        if existing_client:
            self.update_rmc_client(url=base_url, username=username,
                                   password=password, biospassword=biospassword)
        else:
            try:
                self.add_rmc_client(RmcClient(username=username, \
                    password=password, url=base_url, typepath=self.typepath, \
                    biospassword=biospassword, is_redfish=is_redfish))
            except Exception, excp:
                raise excp

        try:
            if base_url == "blobstore://." and \
                            float(self.getiloversion(skipschemas=True)) >= 4.220:
                self.current_client.login()
            elif username and password:
                self.current_client.login()
        except Exception, excp:
            raise excp

        if not skipbuild:
            self.build_monolith(verbose=verbose, path=path, \
                                                        includelogs=includelogs)
            self.save()

    def build_monolith(self, verbose=False, path=None, includelogs=False):
        """Run through the RIS tree to build monolith

        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param path: path to initiate login to.
        :type path: str.
        :param includelogs: flag to determine id logs should be downloaded.
        :type includelogs: boolean.

        """
        monolith = self.current_client.monolith
        inittime = time.clock()
        monolith.load(path=path, includelogs=includelogs)
        endtime = time.clock()

        if verbose:
            sys.stdout.write(u"Monolith build process time: %s\n" % \
                                                        (endtime - inittime))

    def logout(self, url=None):
        """Main function for logout command

        :param url: the URL for the logout request.
        :type url: str.

        """
        sessionlocs = []
        self._validationmanager = None
        self._iloversion = None

        try:
            self.current_client.monolith.killthreads()
        except Exception:
            pass

        try:
            self.current_client.logout()
        except Exception:
            sessionlocs = self.deletelogoutfunction(url)
        else:
            self.deletelogoutfunction(url)

        for session in sessionlocs:
            try:
                self.delete_handler(session[0], url=session[1], \
                            sessionid=session[2], silent=True, service=True)
            except:
                pass
        self.remove_rmc_client(url)
        self.save()

        cachedir = self.config.get_cachedir()
        if cachedir:
            try:
                shutil.rmtree(cachedir)
            except Exception:
                pass

    def get(self, selector=None):
        """Main function for get command

        :param selector: the type selection for the get operation.
        :type selector: str.
        :returns: returns a list from get operation

        """
        results = list()

        instances = self.get_selection()
        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        for instance in instances:
            currdict = instance.resp.dict

            # apply patches to represent current edits
            for patch in instance.patches:
                currdict = jsonpatch.apply_patch(currdict, patch)

            if selector:
                jsonpath_expr = jsonpath_rw.parse(u'%s' % selector)
                matches = jsonpath_expr.find(currdict)
                temp_dict = OrderedDict()

                for match in matches:
                    json_pstr = u'/%s' % match.full_path
                    json_node = jsonpointer.resolve_pointer(currdict, json_pstr)
                    temp_dict[str(match.full_path)] = json_node
                    results.append(temp_dict)
            else:
                results.append(currdict)

        return results

    def get_save(self, selector=None, currentoverride=False, pluspath=False, \
                                                                onlypath=None):
        """Special main function for get in save command

        :param selector: the type selection for the get operation.
        :type selector: str.
        :param currentoverride: flag to override current selection.
        :type currentoverride: boolean.
        :param pluspath: flag to add path to the results.
        :type pluspath: boolean.
        :param onlypath: flag to enable only that path selection.
        :type onlypath: boolean.
        :returns: returns a list from the get command

        """
        results = list()

        instances = self.get_selection()
        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        for instance in instances:
            if self.get_save_helper(instance.resp.request.path, instances)\
                                                     and not currentoverride:
                continue
            elif onlypath:
                if not onlypath == instance.resp.request.path:
                    continue

            currdict = instance.resp.dict

            # apply patches to represent current edits
            for patch in instance.patches:
                currdict = jsonpatch.apply_patch(currdict, patch)

            if selector:
                for item in currdict.iterkeys():
                    if selector.lower() == item.lower():
                        selector = item
                        break

                try:
                    jsonpath_expr = jsonpath_rw.parse(u'"%s"' % selector)
                except Exception, excp:
                    raise InvalidCommandLineError(excp)

                matches = jsonpath_expr.find(currdict)
                temp_dict = OrderedDict()

                for match in matches:
                    json_pstr = u'/%s' % match.full_path
                    json_node = jsonpointer.resolve_pointer(currdict, json_pstr)
                    temp_dict[str(match.full_path)] = json_node

                results.append(temp_dict)
            else:
                if pluspath:
                    results.append({instance.resp.request.path: currdict})
                else:
                    results.append(currdict)

        return results

    def get_save_helper(self, path, instances):
        """helper function for save helper to remove non /settings section

        :param path: originating path for the current instance.
        :type path: str.
        :param instances: current retrieved instances.
        :type instances: dict.
        :returns: returns skip boolean

        """
        skip = False

        for item in instances:
            if (path + "/settings").lower() == (item.resp.request.path).lower():
                skip = True
                break
            elif (path + "settings/").lower() == \
                                            (item.resp.request.path).lower():
                skip = True
                break

        return skip

    def set(self, selector=None, val=None, latestschema=False, \
                                                        uniqueoverride=False):
        """Main function for set command

        :param selector: the type selection for the set operation.
        :type selector: str.
        :param val: value for the property to be modified.
        :type val: str.
        :param latestschema: flag to determine if we should use smart schema.
        :type latestschema: boolean.
        :param uniqueoverride: flag to determine override for unique properties.
        :type uniqueoverride: str.
        :returns: returns a status or list of changes set

        """
        results = list()
        regloc = None
        nochangesmade = False
        patchremoved = False

        iloversion = self.getiloversion()
        type_str = self.current_client.monolith._typestring
        validation_manager = self.get_validation_manager(iloversion)
        (instances, _) = self.get_selection(setenable=True)

        if not instances or len(instances) == 0:
            raise NothingSelectedSetError()

        if selector:
            for instance in instances:
                self.checkforetagchange(instance=instance)

        (instances, attributeregistry) = self.get_selection(setenable=True)
        if selector:
            for instance in instances:
                if self.validate_headers(instance):
                    continue
                else:
                    nochangesmade = True

                currdict = instance.resp.dict
                if latestschema:
                    schematype, regtype = self.latestschemahelper(currdict, \
                                                          validation_manager)
                else:
                    schematype = currdict[type_str]
                    try:
                        regtype = attributeregistry[instance.type]
                    except Exception:
                        pass

                try:
                    if attributeregistry[instance.type]:
                        regfound = validation_manager.find_bios_registry(\
                                                                        regtype)
                except Exception:
                    regfound = validation_manager.find_schema(schematype)

                if self.current_client.monolith.is_redfish and not \
                                        isinstance(regfound, RepoRegistryEntry):
                    regfound = self.get_handler(regfound[u'@odata.id'], \
                                verbose=False, service=True, silent=True).obj
                    regloc = regfound

                    regfound = RepoRegistryEntry(regfound)

                if not regfound:
                    LOGGER.warn(u"Unable to locate registry/schema for '%s'", \
                                                            currdict[type_str])
                    continue
                elif float(iloversion) >= 4.210:
                    try:
                        locationdict = self.geturidict(regfound.Location[0])
                        self.check_type_and_download(\
                                self.current_client.monolith, \
                                locationdict, skipcrawl=True, loadtype='ref')
                    except Exception, excp:
                        raise excp

                for item in currdict.iterkeys():
                    if selector.lower() == item.lower():
                        selector = item
                        break

                newdict = currdict.copy()
                jsonpath_expr = jsonpath_rw.parse(u'%s' % selector)
                matches = jsonpath_expr.find(currdict)

                if not matches:
                    self.warning_handler("Property not found in selection " \
                         "'%s', skipping '%s'\n" % (instance.type, selector))
                    nochangesmade = False

                for match in matches:
                    listfound = False
                    newdict = currdict.copy()
                    json_pstr = u'/%s' % match.full_path
                    val = self.checkforintvalue(selector, val, iloversion, \
                                                validation_manager, instance)

                    if val:
                        if str(val)[0] == "[" and str(val)[-1] == "]":
                            json_node = jsonpointer.set_pointer(newdict, \
                                json_pstr, '"' + str(val) + '"', inplace=True)
                        else:
                            listfound = True
                    else:
                        listfound = True

                    if listfound:
                        json_node = jsonpointer.set_pointer(newdict, \
                                                json_pstr, val, inplace=True)

                    json_node = jsonpointer.resolve_pointer(newdict, json_pstr)

                    entrydict = None
                    entrymono = None

                    if float(iloversion) >= 4.210:
                        entrydict = currdict
                        entrymono = self.current_client.monolith

                    try:
                        if attributeregistry[instance.type]:
                            valman = validation_manager.bios_validate(\
                                    newdict, attributeregistry[instance.type], \
                                    selector, currdict=entrydict, \
                                    monolith=entrymono)

                            if valman == 'readonly':
                                self.warning_handler("Property is read-only" \
                                                 " skipping '%s'\n" % selector)
                                continue
                            elif valman == 'unique' and not uniqueoverride:
                                self.warning_handler("Property is unique to " \
                                     "the system skipping '%s'\n" % selector)
                                continue
                    except Exception:
                        if not validation_manager.validate(newdict, \
                                       selector=selector, currdict=entrydict, \
                                       monolith=entrymono, regloc=regloc):
                            self.warning_handler("Property is " \
                                        "read-only skipping '%s'.\n" % selector)
                            continue

                    validation_errors = validation_manager.get_errors()
                    if validation_errors and len(validation_errors) > 0:
                        raise ValidationError(validation_errors)

                    patch = jsonpatch.make_patch(currdict, newdict)

                    if patch:
                        for item in instance.patches:
                            if patch == item:
                                return

                            try:
                                if item[0]["path"] == patch.patch[0]["path"]:
                                    instance.patches.remove(item)
                            except Exception:
                                if item.patch[0]["path"] == \
                                                        patch.patch[0]["path"]:
                                    instance.patches.remove(item)

                        instance.patches.append(patch)
                        results.append({selector:json_node})

                    if not patch:
                        for item in instance.patches:
                            try:
                                entry = item.patch[0]["path"].replace('/', '')
                                value = item.patch[0]["value"]
                            except Exception:
                                entry = item[0]["path"].replace('/', '')
                                value = item[0]["value"]

                            if entry == selector and str(value) not in str(val):
                                if currdict[selector] == val:
                                    instance.patches.remove(item)
                                    patchremoved = True
                                    nochangesmade = True

        if not nochangesmade:
            return "No entries found"
        if patchremoved:
            return "reverting"
        else:
            return results

    def validate_headers(self, instance, verbose=False):
        """Module to check read-only property before patching.

        :param instance: instace of the property to check
        :type instance: Rest response object.
        :param verbose: enable to print more operations
        :type verbose: bool
        """

        skip = False

        try:
            if not any("PATCH" in x for x in instance.resp._http_response.msg.\
                                                                    headers):
                if verbose:
                    self.warning_handler(u'Skipping read-only path: %s\n' % \
                                                    instance.resp.request.path)
                skip = True
        except:
            try:
                for item in instance.resp._headers:
                    if item.keys()[0] == "allow":
                        if not "PATCH" in item.values()[0]:
                            if verbose:
                                self.warning_handler(u'Skipping read-only ' \
                                     'path: %s' % instance.resp.request.path)

                            skip = True
                            break
            except:
                if not ("allow" in instance.resp._headers and "PATCH" in \
                                            instance.resp._headers["allow"]):
                    if verbose:
                        self.warning_handler(u'Skipping read-only path: ' \
                                            '%s\n' % instance.resp.request.path)
                    skip = True
                elif not "allow" in instance.resp._headers:
                    if verbose:
                        self.warning_handler(u'Skipping read-only path: %s\n' \
                                                % instance.resp.request.path)
                    skip = True

        return skip

    def loadset(self, dicttolist=None, selector=None, val=None, newargs=None,\
                                    latestschema=False, uniqueoverride=False):
        """Optimized version of the old style of set properties

        :param selector: the type selection for the set operation.
        :type selector: str.
        :param val: value for the property to be modified.
        :type val: str.
        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :param latestschema: flag to determine if we should use smart schema.
        :type latestschema: boolean.
        :param uniqueoverride: flag to determine override for unique properties.
        :type uniqueoverride: str.
        :returns: returns a status or a list of set properties

        """
        results = list()

        if (selector and val is not None) and not dicttolist:
            dicttolist = [(selector, val)]
        elif dicttolist is None and not newargs:
            return results
        elif (selector and val and dicttolist) or (newargs and not val):
            return False

        nochangesmade = False
        patchremoved = False
        iloversion = self.getiloversion()
        biosmode = False
        settingskipped = False
        nametype = self.typepath.defs.attname
        validation_manager = self.get_validation_manager(iloversion)
        (instances, _) = self.get_selection(setenable=True)

        if not instances or len(instances) == 0:
            raise NothingSelectedSetError()

        if selector:
            for instance in instances:
                self.checkforetagchange(instance=instance)
        (instances, attributeregistry) = self.get_selection(setenable=True)

        newarg = None
        if newargs:
            (name, value) = newargs[-1].split('=')
            outputline = '/'.join(newargs[:-1]) + "/" + name
            newarg = newargs[:-1]
            newarg.append(name)
            dicttolist = [(name, value)]

        for instance in instances:
            if self.validate_headers(instance):
                continue
            else:
                nochangesmade = True

            currdict = instance.resp.dict
            model, biosmode, _ = self.get_model(currdict, validation_manager, \
                                instance, iloversion, attributeregistry, \
                                latestschema, newarg)

            for ind in range(len(dicttolist)):
                try:
                    dicttolist[ind] = (next(key for key in model.keys() if \
                                    key.lower() == dicttolist[ind][0].lower()),\
                                     dicttolist[ind][1])
                except:
                    pass

            if model:
                if biosmode:
                    validator = map(model.get_validator_bios, (x[0] for x in \
                                  dicttolist))
                else:
                    validator = map(model.get_validator, (x[0] for x in \
                                  dicttolist))

                if validator:
                    try:
                        convert = [isinstance(x, redfish.ris.validation.\
                                      IntegerValidator) for x in validator]
                        indices = [i for i, j in enumerate(convert) if j]

                        for item in indices:
                            dicttolist[item] = (dicttolist[item][0], \
                                                    int(dicttolist[item][1]))
                    except Exception:
                        convert = [isinstance(x, redfish.ris.validation.\
                                      IntegerValidator) for x in validator]
                        indices = [i for i, j in enumerate(convert) if j]

                        for item in indices:
                            if not dicttolist[item][1]:
                                dicttolist[item] = (dicttolist[item][0], \
                                                    dicttolist[item][1])
                            else:
                                dicttolist[item] = (dicttolist[item][0], \
                                                    int(dicttolist[item][1]))

            currdictcopy = copy.deepcopy(currdict)
            templist = []

            if newargs and len(dicttolist)==1 :
                for i in range(len(newargs)):
                    for item in currdictcopy.iterkeys():
                        if newarg[i].lower() == item.lower():
                            newarg[i] = item

                            if not i == (len(newargs) - 1):
                                currdictcopy = currdictcopy[item]
                            else:
                                dicttolist = [(item, dicttolist[0][1])]

                            break
            else:
                items = currdict.keys()
                items = sorted(items)
                itemslower = [x.lower() for x in items]

                try:
                    for ind, item in enumerate(dicttolist):
                        try:
                            if not isinstance(item[1], list):
                                dicttolist[ind] = items[itemslower.index(\
                                                    item[0].lower())], item[1]
                            else:
                                templist.append(item[0])
                        except ValueError, excp:
                            self.warning_handler("Skipping property {0}, not " \
                                 "found in current server.\n".format(item[0]))

                            templist.append(item[0])
                            settingskipped = True

                    if templist:
                        dicttolist = [x for x in dicttolist if x not in \
                                                                    templist]
                except Exception, excp:
                    raise excp

            selectors = [x[0] for x in dicttolist]
            readonly = list()
            if model and biosmode:
                for item in model.Attributes:
                    try:
                        if (item[nametype] in selectors) and item["ReadOnly"]:
                            readonly.extend(item[nametype])
                            self.warning_handler("Property is read-only" \
                                             " skipping '%s'\n" % item[nametype])

                            dicttolist = [x for x in dicttolist if x[0] != \
                                                                item[nametype]]
                        try:
                            if (item[nametype] in selectors) and \
                                                item["IsSystemUniqueProperty"] \
                                                        and not uniqueoverride:
                                self.warning_handler("Property is unique to " \
                                                 "the system skipping '%s'\n" \
                                                                % item[nametype])

                                dicttolist = [x for x in dicttolist if x[0] != \
                                                                item[nametype]]
                        except Exception:
                            continue
                    except Exception, excp:
                        raise excp
            elif model:
                templist = []
                for xitem in selectors:
                    try:
                        if model[xitem].readonly:
                            templist.append(xitem)
                    except Exception:
                        templist.append(xitem)
                try:
                    if templist:
                        tempdict = copy.deepcopy(dicttolist)
                        for i in templist:
                            self.warning_handler("Property is read-only "   \
                                                    "skipping '%s'\n" % str(i))

                        dicttolist = [x for x in tempdict if x[0] not in \
                                                                    templist]
                except Exception, excp:
                    raise excp

            if len(dicttolist) < 1:
                return results

            oridict = copy.deepcopy(currdict)
            newdict = copy.deepcopy(currdict)
            patch = None

            if newargs and len(dicttolist)==1 :
                matches = self.setmultiworker(newargs, dicttolist, newdict)

                if not matches:
                    self.warning_handler("Property not found in selection " \
                         "'%s', skipping '%s'\n" % (instance.type, outputline))

                dicttolist = []

            for (itersel, iterval) in dicttolist:
                jsonpath_expr = jsonpath_rw.parse(u'%s' % itersel)
                matches = jsonpath_expr.find(currdict)

                if not matches:
                    self.warning_handler("Property not found in selection " \
                             "'%s', skipping '%s'\n" % (instance.type, itersel))
                    nochangesmade = False

                for match in matches:
                    listfound = False
                    json_pstr = u'/%s' % match.full_path

                    if iterval:
                        if str(iterval)[0] == "[" and str(iterval)[-1] == "]":
                            json_node = jsonpointer.set_pointer(newdict, \
                                            json_pstr, '"' + str(iterval) + \
                                            '"', inplace=True)
                        else:
                            listfound = True
                    else:
                        listfound = True

                    if listfound:
                        json_node = jsonpointer.set_pointer(newdict, \
                                            json_pstr, iterval, inplace=True)

                    json_node = jsonpointer.resolve_pointer(newdict, json_pstr)

                    self.validatechanges(validation_manager=validation_manager, instance=instance,\
                        iloversion=iloversion, attributeregistry=attributeregistry, \
                        newdict=newdict, checkall=True, service=True, silent=True, oridict=oridict)

                    patch = jsonpatch.make_patch(currdict, newdict)

                    if patch:
                        for item in instance.patches:
                            try:
                                if item[0]["path"] == patch.patch[0]["path"]:
                                    instance.patches.remove(item)
                            except Exception:
                                if item.patch[0]["path"] == \
                                                        patch.patch[0]["path"]:
                                    instance.patches.remove(item)

                        instance.patches.append(patch)
                        results.append({itersel:json_node})

                    currdict = newdict.copy()

            if newargs and not dicttolist:
                self.validatechanges(validation_manager=validation_manager, instance=instance,\
                        iloversion=iloversion, attributeregistry=attributeregistry, \
                        newdict=newdict, checkall=True, service=True, silent=True, oridict=oridict)
                patch = jsonpatch.make_patch(currdict, newdict)

                if patch:
                    for item in instance.patches:
                        try:
                            if item[0]["path"] == patch.patch[0]["path"]:
                                instance.patches.remove(item)
                        except Exception:
                            if item.patch[0]["path"] == \
                                                    patch.patch[0]["path"]:
                                instance.patches.remove(item)

                    instance.patches.append(patch)
                    results.append({outputline:val})
                if not patch:
                    for item in instance.patches:
                        try:
                            entry = item.patch[0]["path"].split('/')[1:]
                        except Exception:
                            entry = item[0]["path"].split('/')[1:]
 
                        if len(entry) == len(newarg):
                            check = 0
                            for ind, elem in enumerate(entry):
                                if elem == newarg[ind]:
                                    check += 1
 
                            if check == len(newarg):
                                instance.patches.remove(item)
                                patchremoved = True
                                nochangesmade = True

        if not nochangesmade:
            return results
        if patchremoved:
            return "reverting"
        elif settingskipped is True:
            raise LoadSkipSettingError()
        else:
            return results

    def validatechanges(self, validation_manager=None, instance=None, entrydict=\
                None, entrymono=None, iloversion=None, attributeregistry=None, \
                newdict=None, checkall=True, service=True, silent=True, oridict=None ):
        entrydict = None
        entrymono = None
        if float(iloversion) >= 4.210:
            entrydict = oridict
            entrymono = self.current_client.monolith

        try:
            if attributeregistry[instance.type]:
                validation_manager.bios_validate(newdict, \
                        attributeregistry[instance.type], checkall=True, \
                                    currdict=entrydict, monolith=entrymono)
        except Exception:
            attrreg = validation_manager.validate(newdict, checkall=True, \
                                    currdict=entrydict, monolith=entrymono)
            if isinstance(attrreg, dict):
                attrreg = self.get_handler(attrreg[self.current_client.\
                        monolith._hrefstring], service=True, silent=True)
                attrreg = RepoRegistryEntry(attrreg.dict)
                validation_manager.validate(newdict, checkall=True, \
                                    currdict=entrydict, monolith=entrymono,\
                                    attrreg=attrreg)

        validation_errors = validation_manager.get_errors()
        if validation_errors and len(validation_errors) > 0:
            raise ValidationError(validation_errors)

    def checkforintvalue(self, selector, val, iloversion, validation_manager, \
                                                        instance, newarg=None):
        """Function for integer validation

        :param selector: the type selection for the set operation.
        :type selector: str.
        :param val: value for the property to be modified.
        :type val: str.
        :param iloversion: current systems iLO versions.
        :type iloversion: str.
        :param validation_manager: validation manager object.
        :type validation_manager: validation object.
        :param instance: retrieved instance for a particular section.
        :type instance: str.
        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :returns: returns value for property to be modified

        """
        biosmode = False
        currdict = instance.resp.dict
        (_, attributeregistry) = self.get_selection(setenable=True)

        try:
            if attributeregistry[instance.type]:
                regfound = validation_manager.find_bios_registry(\
                                             attributeregistry[instance.type])
                biosmode = True
        except Exception:
            regfound = validation_manager.find_schema(\
                                              currdict[instance._typestring])

            if self.current_client.monolith.is_redfish and not \
                                    isinstance(regfound, RepoRegistryEntry):
                regfound = self.get_handler(regfound[u'@odata.id'], \
                                verbose=False, service=True, silent=True).obj

        if regfound:
            model, _, _ = self.get_model(currdict, validation_manager, \
                                     instance, iloversion, attributeregistry)

            if model:
                if biosmode:
                    validator = model.get_validator_bios(selector)
                else:
                    validator = model.get_validator(selector, newarg)

                if validator:
                    try:
                        if isinstance(validator, redfish.ris.validation.\
                                      IntegerValidator):
                            val = int(val)
                    except Exception:
                        if isinstance(validator, redfish.ris.validation.\
                                      IntegerValidator):
                            if val:
                                val = int(val)

        return val

    def setmultilevel(self, val=None, newargs=None, latestschema=False):
        """Main function for set multi level command

        :param val: value for the property to be modified.
        :type val: str.
        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :param latestschema: flag to determine if we should use smart schema.
        :type latestschema: boolean.
        :returns: returns a status or a list of set multi level properties

        """
        results = list()
        selector = None
        regloc = None
        nochangesmade = False
        patchremoved = False
        iloversion = self.getiloversion()
        validation_manager = self.get_validation_manager(iloversion)
        type_string = self.current_client.monolith._typestring
        (name, _) = newargs[-1].split('=', 1)
        outputline = '/'.join(newargs[:-1]) + "/" + name

        (instances, _) = self.get_selection(setenable=True)

        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        if newargs:
            for instance in instances:
                self.checkforetagchange(instance=instance)
        (instances, attributeregistry) = self.get_selection(setenable=True)

        if newargs:
            for instance in instances:
                currdict = instance.resp.dict
                currdictcopy = currdict
                newarg = newargs[:-1]
                newarg.append(name)

                for i in range(len(newargs)):
                    for item in currdictcopy.iterkeys():
                        if newarg[i].lower() == item.lower():
                            selector = item
                            newarg[i] = item

                            if not newarg[i].lower() == newarg[-1].lower():
                                currdictcopy = currdictcopy[item]
                                break

                if not selector:
                    continue

                if self.validate_headers(instance):
                    continue
                else:
                    nochangesmade = True

                if latestschema:
                    schematype, regtype = self.latestschemahelper(currdict, \
                                                          validation_manager)
                else:
                    schematype = currdict[type_string]

                    try:
                        regtype = attributeregistry[instance.type]
                    except Exception:
                        pass

                try:
                    if attributeregistry[instance.type]:
                        regfound = validation_manager.find_bios_registry(\
                                                                        regtype)
                except Exception:
                    regfound = validation_manager.find_schema(schematype)

                if self.current_client.monolith.is_redfish and not \
                                        isinstance(regfound, RepoRegistryEntry):
                    regfound = self.get_handler(regfound[u'@odata.id'], \
                                verbose=False, service=True, silent=True).obj
                    regloc = regfound

                if not regfound:
                    LOGGER.warn(u"Unable to locate registry/schema for '%s'",\
                                                        currdict[type_string])
                    continue
                elif float(iloversion) >= 4.210:
                    try:
                        locationdict = self.geturidict(regfound.Location[0])
                        self.check_type_and_download(\
                                self.current_client.monolith, locationdict, \
                                skipcrawl=True, loadtype='ref')
                    except Exception, excp:
                        raise excp

                newdict = copy.deepcopy(currdict)

                matches = self.setmultiworker(newargs, newdict)

                if not matches:
                    self.warning_handler("Property not found in selection " \
                         "'%s', skipping '%s'\n" % (instance.type, outputline))
                else:
                    entrydict = None
                    entrymono = None

                    if float(iloversion) >= 4.210:
                        entrydict = currdict
                        entrymono = self.current_client.monolith

                    try:
                        if attributeregistry[instance.type]:
                            if not validation_manager.bios_validate(\
                                    newdict, attributeregistry[instance.type], \
                                    selector, currdict=entrydict, \
                                    monolith=entrymono):
                                self.warning_handler("Property is read-only" \
                                                 " skipping '%s'\n" % selector)
                                continue
                    except Exception:
                        selector = newarg[-1]
                        newdictcopy = newdict

                        for elem in newarg:
                            for item in newdictcopy.iterkeys():
                                if elem.lower() == item.lower():
                                    if not elem.lower() == newarg[-1].lower():
                                        newdictcopy = newdictcopy[item]

                        newdictcopy[type_string] = newdict[type_string]
                        currdictcopy[type_string] = currdict[type_string]

                        if not validation_manager.validate(newdictcopy, \
                                    selector=selector, currdict=currdictcopy, \
                                    monolith=entrymono, newarg=newarg, \
                                    regloc=regloc):
                            self.warning_handler("Property is read-only " \
                                                "skipping '%s'\n" % selector)
                            continue

                    validation_errors = validation_manager.get_errors()
                    if validation_errors and len(validation_errors) > 0:
                        raise ValidationError(validation_errors)

                    patch = jsonpatch.make_patch(currdict, newdict)

                    if patch:
                        for item in instance.patches:
                            if patch == item:
                                return

                            try:
                                if item[0]["path"] == patch.patch[0]["path"]:
                                    instance.patches.remove(item)
                            except Exception:
                                if item.patch[0]["path"] == \
                                                        patch.patch[0]["path"]:
                                    instance.patches.remove(item)

                        instance.patches.append(patch)
                        results.append({outputline:val})

                    if not patch:
                        for item in instance.patches:
                            try:
                                entry = item.patch[0]["path"].split('/')[1:]
                            except Exception:
                                entry = item[0]["path"].split('/')[1:]

                            if len(entry) == len(newarg):
                                check = 0

                                for ind, elem in enumerate(entry):
                                    if elem == newarg[ind]:
                                        check += 1

                                if check == len(newarg):
                                    instance.patches.remove(item)
                                    patchremoved = True
                                    nochangesmade = True

        if not nochangesmade:
            return "No entries found"
        if patchremoved:
            return "reverting"
        else:
            return results

    def setmultiworker(self, newargs, change, currdict, current=0):
        """Helper function for multi level set function

        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param current: current location holder.
        :type current: list.
        :returns: returns boolean on whether properties are found

        """
        found = False

        if not newargs[current] == newargs[-1]:
            for attr, val in currdict.iteritems():
                if attr.lower() == newargs[current].lower():
                    current += 1
                    found = self.setmultiworker(newargs, change, val, current)
                    continue
                else:
                    continue
        else:
            for attr, val in currdict.iteritems():
                if attr.lower() == change[0][0].lower():
                    currdict[attr] = change[0][1]
                    found = True

        return found

    def info(self, selector=None, ignorelist=None, dumpjson=False, \
                            autotest=False, newarg=None, latestschema=False):
        """Main function for info command

        :param selector: the type selection for the get operation.
        :type selector: str.
        :param ignorelist: list that contains keys to be removed from output.
        :type ignorelist: list.
        :param dumpjson: flag to determine if output should be printed out.
        :type dumpjson: boolean.
        :param autotest: flag to determine if this part of automatic testing.
        :type autotest: boolean.
        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :param latestschema: flag to determine if we should use smart schema.
        :type latestschema: boolean.
        :returns: returns a list of keys from current dict that are not ignored

        """
        results = list()
        iloversion = self.getiloversion()
        validation_manager = self.get_validation_manager(iloversion)
        (instances, attributeregistry) = self.get_selection(setenable=True)

        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        for instance in instances:
            if self.get_save_helper(instance.resp.request.path, instances):
                continue

            bsmodel = None
            biosmode = False
            currdict = instance.resp.dict

            if selector:
                if newarg:
                    currdictcopy = currdict

                    for ind, elem in enumerate(newarg):
                        if isinstance(currdictcopy, dict):
                            for item in currdictcopy.iterkeys():
                                if elem.lower() == item.lower():
                                    selector = item
                                    newarg[ind] = item

                                    if not elem.lower() == newarg[-1].lower():
                                        currdictcopy = currdictcopy[item]
                                        break
                        else:
                            break
                else:
                    for item in currdict.iterkeys():
                        if selector.lower() == item.lower():
                            selector = item
                            break

            if self.current_client.monolith._typestring in currdict:
                model, biosmode, bsmodel = self.get_model(currdict, \
                                  validation_manager, instance, iloversion, \
                                  attributeregistry, latestschema, newarg, \
                                  autotest=autotest)

            if not model and not bsmodel:
                if newarg:
                    self.warning_handler("No data available for entry: '%s'\n" \
                                                            % "/".join(newarg))

                    if autotest:
                        return True
                    else:
                        break
                else:
                    LOGGER.warn(u"Unable to locate registry model for " \
                                                            ":'%s'", selector)
                    continue

            if selector:
                if newarg:
                    currdict = currdictcopy

                jsonpath_expr = jsonpath_rw.parse(u'"%s"' % selector)
                matches = jsonpath_expr.find(currdict)

                if matches:
                    for match in matches:
                        json_pstr = u'/%s' % match.full_path
                        jsonpointer.JsonPointer(json_pstr)

                        for key in currdict:
                            matchpath = u'%s' % match.full_path
                            if not key.lower() == matchpath.lower():
                                continue

                            if biosmode:
                                found = model.get_validator_bios(key)

                                if not found and bsmodel:
                                    found = bsmodel.get_validator(key)
                            else:
                                found = model.get_validator(key)

                            if found:
                                if dumpjson:
                                    print found
                                elif autotest:
                                    return True
                                else:
                                    #TODO: find a way to not print
                                    results.append("Success")
                                    found.print_help(selector, out=sys.stdout)
                            else:
                                self.warning_handler("No data available for " \
                                         "entry: '%s'\n" % ("/".join(newarg) \
                                                    if newarg else selector))
                                results.append("none")
                else:
                    self.warning_handler("Entry '%s' not found in current" \
                                            " selection\n" % ("/".join(newarg) \
                                                      if newarg else selector))
                    results.append("none")

            else:
                if currdict[self.typepath.defs.typestring].startswith("#Bios."):
                    try:
                        currdict = currdict['Attributes']
                    except:
                        pass
                for key in currdict:
                    if key not in ignorelist and not '@odata' in key.lower():
                        results.append(key)

        return results

    def getcollectionmembers(self, path):
        """Returns collection/item lists of the provided path
        :param path: path to return .
        :type path: string.
        :returns: returns collection list
        """
        if self.typepath.defs.isgen10:
            if path.endswith('/'):
                path += '?$expand=.'
            else:
                path += '/?$expand=.'

        members = self.get_handler(path,service=True, silent=True)
        if members:
            try:
                if self.typepath.defs.isgen10:
                    members = members.dict['Members']
                else:
                    members = members.dict['Items']
            except:
                members = []

        return members

    def getbiosfamilyandversion(self):
        """Function that returns the current BIOS family"""
        (founddir, entrytype) = \
                        self.check_types_version(self.current_client.monolith)

        if founddir:
            self.check_types_exists(entrytype, "ComputerSystem.", \
                                self.current_client.monolith, skipcrawl=True)

        monolith = self.current_client.monolith

        for ristype in monolith.types:
            if u'Instances' in monolith.types[ristype]:
                for instance in monolith.types[ristype][u'Instances']:
                    if "computersystem." in instance.type.lower():
                        try:
                            if "Current" in instance.resp.obj["Bios"]:
                                oemjson = instance.resp.obj["Bios"]["Current"]
                                parts = oemjson["VersionString"].split(" ")
                                return (parts[0], parts[1][1:])
                            else:
                                parts = instance.resp.obj["BiosVersion"]\
                                                                .split(" ")
                                return (parts[0], parts[1][1:])
                        except Exception:
                            pass

        return (None, None)

    def getiloversion(self, skipschemas=False):
        """Function that returns the current iLO version

        :param skipschemas: flag to determine whether to skip schema download.
        :type skipschemas: boolean.
        :returns: returns current iLO version

        """

        iloversion = self._iloversion

        if not self._iloversion:
            results = self.get_handler(self.current_client._rest_client.\
                                       default_prefix, silent=True, service=True)
    
            try:
                if results.dict["Oem"][self.typepath.defs.oemhp]["Manager"]:
                    oemjson = results.dict["Oem"][self.typepath.defs.\
                                                                oemhp]["Manager"]
                    ilogen = oemjson[0]["ManagerType"]
                    ilover = oemjson[0]["ManagerFirmwareVersion"]
                    iloversion = ilogen.split(' ')[-1] + '.' + \
                                                        ''.join(ilover.split('.'))
            except Exception:
                pass
            self._iloversion = iloversion

        if not skipschemas:
            if iloversion and float(iloversion) > 4.210:
                self.verifyschemasdownloaded(self.current_client.monolith)

        return iloversion

    def status(self):
        """Main function for status command"""
        iloversion = self.getiloversion()
        validation_manager = self.get_validation_manager(iloversion)

        finalresults = list()
        monolith = self.current_client.monolith
        (_, attributeregistry) = self.get_selection(setenable=True)

        for ristype in monolith.types:
            if u'Instances' in monolith.types[ristype]:
                for instance in monolith.types[ristype][u'Instances']:
                    results = list()

                    if instance.patches and len(instance.patches) > 0:
                        if isinstance(instance.patches[0], list):
                            results.extend(instance.patches)
                        else:
                            if instance.patches[0]:
                                for item in instance.patches:
                                    results.extend(item)

                    currdict = instance.resp.dict

                    itemholder = list()
                    for mainitem in results:
                        item = copy.deepcopy(mainitem)
                        regfound = None

                        try:
                            if attributeregistry[instance.type]:
                                regfound = validation_manager.\
                                            find_bios_registry(\
                                               attributeregistry[instance.type])
                        except Exception:
                            pass

                        if regfound:
                            model, _, _ = self.get_model(currdict, \
                                             validation_manager, instance, \
                                             iloversion, attributeregistry)

                            if model:
                                try:
                                    validator = \
                                        model.get_validator_bios(item[0]\
                                                                ["path"][1:])
                                except Exception:
                                    validator = model.get_validator_bios(\
                                                             item["path"][1:])

                                if validator:
                                    try:
                                        if isinstance(validator, redfish.ris.\
                                                  validation.PasswordValidator):
                                            item[0]["value"] = "******"
                                    except Exception:
                                        if isinstance(validator, redfish.ris.\
                                                  validation.PasswordValidator):
                                            item["value"] = "******"

                        itemholder.append(item)

                    if itemholder:
                        finalresults.append({instance.type: itemholder})

        return finalresults

    def capture(self):
        """Build and return the entire monolith"""
        monolith = self.current_client.monolith
        vistedurls = monolith.get_visited_urls()
 
        monolith.set_visited_urls(list())
        monolith.load(includelogs=True, skipcrawl=False, loadcomplete=True)
        monolith.set_visited_urls(vistedurls)
        
        results = list()
        instances = self.get_selection(selector='"*"')

        for instance in instances:
            currdict = instance.resp.dict
            results.append({instance.resp.request.path: currdict})

        return results

    def commitworkerfunc(self, patch):
        """Helper function for the commit command

        :param patch: dictionary containing all patches to be applied.
        :type patch: dict.
        :returns: returns a dictionary of patches applied

        """
        try:
            entries = patch.patch[0]["path"][1:].split("/")
        except Exception:
            entries = patch[0]["path"][1:].split("/")

        counter = 0
        results = dict()
        for item in reversed(entries):
            if counter == 0:
                boolfound = False

                try:
                    boolfound = isinstance(patch.patch[0]["value"], bool)
                except Exception:
                    boolfound = isinstance(patch[0]["value"], bool)
                try:
                    intfound = isinstance(patch.patch[0]["value"], int)
                except Exception:
                    intfound = isinstance(patch[0]["value"], int)

                if boolfound or intfound:
                    try:
                        results = {item:patch.patch[0]["value"]}
                    except Exception:
                        results = {item:patch[0]["value"]}

                else:
                    try:
                        if patch.patch[0]["value"][0] == '"' and\
                                            patch.patch[0]["value"][-1] == '"':
                            results = {item:patch.patch[0]["value"][1:-1]}
                        else:
                            results = {item:patch.patch[0]["value"]}
                    except Exception:
                        if patch[0]["value"][0] == '"' and\
                                                patch[0]["value"][-1] == '"':
                            results = {item:patch[0]["value"][1:-1]}
                        else:
                            results = {item:patch[0]["value"]}

                counter += 1
            else:
                results = {item:results}

        return results

    def commit(self, out=sys.stdout, verbose=False):
        """Main function for commit command

        :param out: output type for verbosity.
        :type out: output type.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :returns: returns boolean of whether changes were made

        """
        changesmade = False
        instances = self.get_commit_selection()

        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        for instance in instances:
            if self.validate_headers(instance, verbose=verbose):
                continue

            currdict = dict()

            # apply patches to represent current edits
            for patch in instance.patches:
                try:
                    self.checkforetagchange(instance=instance)
                except Exception, excp:
                    raise excp

                if hasattr(patch, 'patch'):
                    if len(patch.patch):
                        if "/" in patch.patch[0]["path"][1:]:
                            newdict = self.commitworkerfunc(patch)

                            if newdict:
                                self.merge_dict(currdict, newdict)
                        else:
                            if isinstance(patch.patch[0]["value"], int):
                                currdict[patch.patch[0]["path"][1:]] = \
                                                        patch.patch[0]["value"]
                            elif not isinstance(patch.patch[0]["value"], bool):
                                if patch.patch[0]["value"]:
                                    if patch.patch[0]["value"][0] == '"' and\
                                        patch.patch[0]["value"][-1] == '"' and\
                                        len(patch.patch[0]["value"]) == 2:
                                        currdict[patch.patch[0]["path"][1:]] = \
                                                                            ''
                                    elif patch.patch[0]["value"][0] == '"' and\
                                        patch.patch[0]["value"][-1] == '"':
                                        line = patch.patch[0]["value"]\
                                                        [2:-2].replace("'", "")
                                        line = line.replace(", ", ",")
                                        currdict[patch.patch[0]["path"]\
                                                        [1:]] = line.split(',')
                                    else:
                                        currdict[patch.patch[0]["path"][1:]] = \
                                                        patch.patch[0]["value"]
                                else:
                                    currdict[patch.patch[0]["path"][1:]] = \
                                                        patch.patch[0]["value"]
                            else:
                                currdict[patch.patch[0]["path"][1:]] = \
                                                    patch.patch[0]["value"]
                else:
                    if "/" in patch[0]["path"][1:]:
                        newdict = self.commitworkerfunc(patch)
                        if newdict:
                            self.merge_dict(currdict, newdict)
                    else:
                        if isinstance(patch[0]["value"], int):
                            currdict[patch[0]["path"][1:]] = patch[0]["value"]
                        elif not isinstance(patch[0]["value"], bool):
                            if patch[0]["value"]:
                                if patch[0]["value"][0] == '"' and\
                                            patch[0]["value"][-1] == '"' and \
                                                    len(patch[0]["value"]) == 2:
                                    currdict[patch[0]["path"][1:]] = ''
                                elif patch[0]["value"][0] == '"' and\
                                                patch[0]["value"][-1] == '"':
                                    currdict[patch[0]["path"][1:]] = \
                                            patch[0]["value"][2:-2].split(',')
                                else:
                                    currdict[patch[0]["path"][1:]] = \
                                                            patch[0]["value"]
                            else:
                                currdict[patch[0]["path"][1:]] = \
                                                            patch[0]["value"]
                        else:
                            currdict[patch[0]["path"][1:]] = patch[0]["value"]

            if currdict:
                changesmade = True
                if verbose:
                    out.write(u'Changes made to path: %s\n' % \
                                                    instance.resp.request.path)

                put_path = instance.resp.request.path
                results = self.current_client.set(put_path, body=currdict, \
                          optionalpassword=self.current_client.bios_password)

                errmessages = self.get_error_messages()
                self.invalid_return_handler(results, errmessages=errmessages)

                if not results.status == 200:
                    raise FailureDuringCommitError("Failed to commit with " \
                                               "error code %d" % results.status)

        return changesmade

    def merge_dict(self, currdict, newdict):
        """Helper function to merge dictionaries

        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param currdict: new selection dictionary.
        :type currdict: dict.

        """
        for k, itemv2 in newdict.items():
            itemv1 = currdict.get(k)

            if isinstance(itemv1, Mapping) and\
                 isinstance(itemv2, Mapping):
                self.merge_dict(itemv1, itemv2)
            else:
                currdict[k] = itemv2

    def get_error_messages(self):
        """Handler of error messages from iLO"""
        errmessages = {}
        reglist = []
        iloversion = self.getiloversion()
        typestr = self.current_client.monolith._typestring
        colstr = self.typepath.defs.collectionstring
        validation_manager = self.get_validation_manager(iloversion)
        if not validation_manager._classes_registry:
            return None
        for reg in validation_manager._classes_registry[0][colstr]:
            try:
                if reg and 'Id' in reg and not 'biosattributeregistry' in \
                                                            reg['Id'].lower():
                    reglist.append(reg['Id'])
                elif reg and 'Schema' in reg and not 'biosattributeregistry' in \
                                                        reg['Schema'].lower():
                    reglist.append(reg['Schema'])
            except:
                if reg:
                    reg = reg[u'@odata.id'].split('/')
                    reg = reg[len(reg)-2]
                    if not 'biosattributeregistry' in reg.lower():
                        reglist.append(reg)

        for reg in reglist:
            regfound = validation_manager.find_registry(reg)

            if regfound and self.current_client.monolith.is_redfish\
                                 and not isinstance(regfound, RepoRegistryEntry):
                regfound = self.get_handler(regfound[u'@odata.id'], \
                                verbose=False, service=True, silent=True).obj
                regfound = RepoRegistryEntry(regfound)
            if not regfound:
                LOGGER.warn(u"Unable to locate registry for '%s'", reg)
            elif float(iloversion) >= 4.210:
                try:
                    locationdict = self.geturidict(regfound.Location[0])
                    self.check_type_and_download(self.current_client.monolith, \
                                     locationdict, skipcrawl=True, loadtype='ref')
                except Exception:
                    pass
            if regfound:
                errmessages[reg] = regfound.get_registry_model(\
                                skipcommit=True, currdict={typestr: reg}, \
                                monolith=self.current_client.monolith, \
                                searchtype=self.typepath.defs.messageregistrytype)

        return errmessages

    def patch_handler(self, put_path, body, verbose=False, url=None, \
                  sessionid=None, headers=None, response=False, silent=False, \
                  optionalpassword=None, providerheader=None, service=False):
        """Main worker function for raw patch command

        :param put_path: the URL path.
        :type put_path: str.
        :param body: the body to the sent.
        :type body: str.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param url: originating URL.
        :type url: str.
        :param sessionid: session id to be used instead of credentials.
        :type sessionid: str.
        :param headers: additional headers to be added to the request.
        :type headers: str.
        :param response: flag to return the response.
        :type response: str.
		:param optionalpassword: provide password for authentication.
        :type optionalpassword: str.
		:param provideheader: provider id for the header.
        :type providerheader: str.
        :param service: flag to determine if minimum calls should be done.
        :type service: boolean.
        :returns: returns RestResponse object containing response data

        """
        errmessages = None

        if sessionid:
            if url == None:
                url = 'blobstore://'
            if not self.typepath.defs:
                self.getgen(url=url)

        (put_path, body) = self.checkpostpatch(body=body, path=put_path, \
                    verbose=verbose, service=False, url=None, sessionid=None, \
                    headers=None, iloresponse=False, silent=True, patch=True)

        if sessionid:

            results = RmcClient(url=url, sessionkey=sessionid, is_redfish=\
                                    self.updatedefinesflag()).\
                                    set(put_path, body=body, headers=headers, \
                                           optionalpassword=optionalpassword, \
                                           providerheader=providerheader)
            service = True
        else:
            results = self.current_client.set(put_path, body=body, \
                        headers=headers, optionalpassword=optionalpassword, \
                        providerheader=providerheader)

        if not silent and not service:
            errmessages = self.get_error_messages()

        if not silent:
            self.invalid_return_handler(results, verbose=verbose, errmessages=errmessages)
        elif results.status == 401:
            raise SessionExpired()

        if response:
            return results

    def get_handler(self, put_path, silent=False, verbose=False, url=None, \
                                sessionid=None, uncache=False, headers=None, \
                                response=False, service=False):
        """main worker function for raw get command

        :param put_path: the URL path.
        :type put_path: str.
        :param silent: flag to determine if no output should be done.
        :type silent: boolean.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param url: originating URL.
        :type url: str.
        :param sessionid: session id to be used instead of credentials.
        :type sessionid: str.
        :param uncache: flag to not store the data downloaded into cache.
        :type uncache: boolean.
        :param headers: additional headers to be added to the request.
        :type headers: str.
        :param response: flag to return the response.
        :type response: str.
        :param service: flag to determine if minimum calls should be done.
        :type service: boolean.
        :returns: returns a RestResponse object from client's get command

        """
        errmessages = None

        if sessionid:
            if url == None:
                url = 'blobstore://'
            if not self.typepath.defs:
                self.getgen(url=url)

            results = RmcClient(url=url, sessionkey=sessionid, is_redfish=\
                                                    self.updatedefinesflag()).\
                                                get(put_path, headers=headers)
            service = True
        else:
            results = self.current_client.get(put_path, uncache=uncache, \
                                                                headers=headers)

        if not silent and not service:
            errmessages = self.get_error_messages()

        if not silent:
            self.invalid_return_handler(results, verbose=verbose, \
                                                        errmessages=errmessages)
        elif results.status == 401:
            raise SessionExpired()

        if results.status == 200 or response:
            return results
        else:
            return None

    def post_handler(self, put_path, body, verbose=False, url=None, \
                             sessionid=None, headers=None, response=False, \
                             silent=False, providerheader=None, service=False):
        """Main worker function for raw post command

        :param put_path: the URL path.
        :type put_path: str.
        :param body: the body to the sent.
        :type body: str.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param url: originating URL.
        :type url: str.
        :param sessionid: session id to be used instead of credentials.
        :type sessionid: str.
        :param headers: additional headers to be added to the request.
        :type headers: str.
        :param response: flag to return the response.
        :type response: str.
        :param provideheader: provider id for the header.
        :type providerheader: str.
        :param service: flag to determine if minimum calls should be done.
        :type service: boolean.
        :returns: returns a RestResponse from client's Post command

        """
        errmessages = None

        if sessionid:
            if url == None:
                url = 'blobstore://'
            if not self.typepath.defs:
                self.getgen(url=url)

        (put_path, body) = self.checkpostpatch(body=body, path=put_path, \
                    verbose=verbose, service=False, url=None, sessionid=None,\
                    headers=None, iloresponse=False, silent=True)

        if sessionid:
            results = RmcClient(url=url, sessionkey=sessionid, is_redfish=\
                                self.updatedefinesflag()).\
                                toolpost(put_path, body=body, headers=headers, \
                                        providerheader=providerheader)
            service = True
        else:
            results = self.current_client.toolpost(put_path, body=body, \
                                headers=headers, providerheader=providerheader)

        if not silent and not service:
            errmessages = self.get_error_messages()

        if not silent:
            self.invalid_return_handler(results, verbose=verbose, errmessages=errmessages)
        elif results.status == 401:
            raise SessionExpired()

        if response:
            return results

    def put_handler(self, put_path, body, verbose=False, url=None, \
                sessionid=None, headers=None, response=False, silent=False, \
                optionalpassword=None, providerheader=None, service=False):
        """Main worker function for raw put command

        :param put_path: the URL path.
        :type put_path: str.
        :param body: the body to the sent.
        :type body: str.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param url: originating URL.
        :type url: str.
        :param sessionid: session id to be used instead of credentials.
        :type sessionid: str.
        :param headers: additional headers to be added to the request.
        :type headers: str.
        :param response: flag to return the response.
        :type response: str.
        :param optionalpassword: provide password for authentication.
        :type optionalpassword: str.
        :param provideheader: provider id for the header.
        :type providerheader: str.
        :param service: flag to determine if minimum calls should be done.
        :type service: boolean.
        :returns: returns a RestResponse object from client's Put command

        """
        errmessages = None

        if sessionid:
            if url == None:
                url = 'blobstore://'
            if not self.typepath.defs:
                self.getgen(url=url)

            results = RmcClient(url=url, sessionkey=sessionid, is_redfish=\
                                self.updatedefinesflag()).toolput(put_path, \
                                       body=body, headers=headers, \
                                       optionalpassword=optionalpassword, \
                                       providerheader=providerheader)
            service = True
        else:
            results = self.current_client.toolput(put_path, body=body, \
                          headers=headers, optionalpassword=optionalpassword, \
                          providerheader=providerheader)

        if not silent and not service:
            errmessages = self.get_error_messages()

        if not silent:
            self.invalid_return_handler(results, verbose=verbose, errmessages=errmessages)
        elif results.status == 401:
            raise SessionExpired()

        if response:
            return results

    def delete_handler(self, put_path, verbose=False, url=None, \
                                    sessionid=None, headers=None, silent=True, \
                                    providerheader=None, service=False):
        """Main worker function for raw delete command

        :param put_path: the URL path.
        :type put_path: str.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param url: originating URL.
        :type url: str.
        :param sessionid: session id to be used instead of credentials.
        :type sessionid: str.
        :param headers: additional headers to be added to the request.
        :type headers: str.
        :param silent: flag to disable output.
        :type silent: boolean.
        :param provideheader: provider id for the header.
        :type providerheader: str.
        :param service: flag to determine if minimum calls should be done.
        :type service: boolean.
        :returns: returns a RestResponse object from client's Delete command

        """
        errmessages = None

        if sessionid:
            if url == None:
                url = 'blobstore://'
            if not self.typepath.defs:
                rf = None
                self.getgen(url=url)
                rf=self.updatedefinesflag(redfishflag=rf)

            results = RmcClient(url=url, sessionkey=sessionid, is_redfish=\
                                                    self.updatedefinesflag()).\
                tooldelete(put_path, headers=headers, providerheader=providerheader)
            service = True
        else:
            results = self.current_client.tooldelete(put_path, \
                                 headers=headers, providerheader=providerheader)

        if not silent and not service:
            errmessages = self.get_error_messages()

        if not silent:
            self.invalid_return_handler(results, verbose=verbose, errmessages=errmessages)
        elif results.status == 401:
            raise SessionExpired()

        return results

    def head_handler(self, put_path, verbose=False, url=None, sessionid=None, \
                                                silent=False, service=False):
        """Main worker function for raw head command

        :param put_path: the URL path.
        :type put_path: str.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param url: originating URL.
        :type url: str.
        :param sessionid: session id to be used instead of credentials.
        :type sessionid: str.
        :param service: flag to determine if minimum calls should be done.
        :type service: boolean.
        :returns: returns a RestResponse object from client's Head command

        """
        errmessages = None

        if sessionid:
            if url == None:
                url = 'blobstore://'
            if not self.typepath.defs:
                self.getgen(url=url)

            results = RmcClient(url=url, sessionkey=sessionid, is_redfish=\
                                                    self.updatedefinesflag()).\
                                                                head(put_path)
            service = True
        else:
            results = self.current_client.head(put_path)

        if not silent and not service:
            errmessages = self.get_error_messages()

        if not silent:
            self.invalid_return_handler(results, verbose=verbose, errmessages=errmessages)
        elif results.status == 401:
            raise SessionExpired()

        if results.status == 200:
            return results
        else:
            return None

    _QUERY_PATTERN = re.compile(r'(?P<instance>[\w\.]+)(:(?P<xpath>.*))?')
    def _parse_query(self, querystr):
        """Parse query and return as a dict. TODO probably need to move"""
        """ this into its own class if it gets too complicated

        :param querystr: query string.
        :type querystr: str.
        :returns: returns a dict of parsed query

        """
        qmatch = RmcApp._QUERY_PATTERN.search(querystr)
        if not qmatch:
            raise InvalidSelectionError(u"Unable to locate instance for " \
                                                            "'%s'" % querystr)

        qgroups = qmatch.groupdict()

        return dict(instance=qgroups[u'instance'], \
                                            xpath=qgroups.get(u'xpath', None))

    def invalid_return_handler(self, results, verbose=False, errmessages=None):
        """Main worker function for handling all error messages

        :param results: dict of the results.
        :type results: sict.
		:param errmessages: dict of lists containing the systems error messages.
        :type errmessages: dict.
        :param verbose: flag to enable additional verbosity.
        :type verbose: boolean.

        """
        output = ''
        try:
            contents = results.dict["Messages"][0]["MessageID"].split('.')
        except Exception:
            try:
                contents = results.dict["error"]["@Message.ExtendedInfo"][0]\
                                                        ["MessageId"].split('.')
            except Exception:
                if results.status == 200 or results.status == 201:
                    if verbose:
                        sys.stdout.write(u"[%d] The operation completed " \
                                            "successfully.\n" % results.status)
                    else:
                        self.warning_handler(u"[%d] The operation completed " \
                                            "successfully.\n" % results.status)
                else:
                    self.warning_handler(u"[%d] No message returned by iLO.\n" %\
                                                                results.status)
                    sys.stdout.write(u"iLO response with code [%d].\n"%(\
                                                            results.status))
                    raise IloResponseError("")
                return

        if results.status == 401 and not contents[-1].lower() == \
                                                        'insufficientprivilege':
            raise SessionExpired()
        elif results.status == 403:
            raise IdTokenError()
        elif errmessages:
            for messagetype in errmessages.keys():
                if contents[0] == messagetype:
                    try:
                        if errmessages[messagetype][contents[-1]]["NumberOfArgs"] == 0:
                            output = errmessages[messagetype][contents[-1]]["Message"]
                        else:
                            output = errmessages[messagetype][contents[-1]]["Description"]

                        if verbose:
                            sys.stdout.write(u"[%d] %s\n" % (results.status, \
                                                                        output))
                        if results.status is not 200 and results.status is not 201:
                            sys.stdout.write(u"iLO response with code [%d]: %s\n"%(\
                                                        results.status, output))
                            raise IloResponseError("")
                        break
                    except IloResponseError as excp:
                        raise excp
                    except Exception:
                        pass
        else:
            if results.status == 200 or results.status == 201:
                if verbose:
                    sys.stdout.write(u"[%d] The operation completed " \
                                            "successfully.\n" % results.status)
                else:
                    self.warning_handler(u"The operation completed "\
                                                            "successfully.\n")
            elif contents:
                sys.stdout.write(u"iLO responsed with code {0}: {1}\n".format(\
                                                        results.status, contents))
                raise IloResponseError()
            else:
                self.warning_handler(u"[%d] No message returned.\n" % \
                                                                results.status)

    def select(self, query, sel=None, val=None):
        """Main function for select command

        :param query: query string.
        :type query: str.
        :param sel: the type selection for the select operation.
        :type sel: str.
        :param val: value for the property to be modified.
        :type val: str.
        :returns: returns a list of selected items

        """
        if query:
            if isinstance(query, list):
                if len(query) == 0:
                    raise InstanceNotFoundError(u"Unable to locate instance " \
                                                            "for '%s'" % query)
                else:
                    query = query[0]

            if val:
                if (str(val)[0] == str(val)[-1]) and \
                                                str(val).endswith(("'", '"')):
                    val = val[1:-1]

            query = self.checkselectforgen(query)
            selection = self.get_selection(selector=query, sel=sel, val=val)

            if selection and len(selection) > 0:
                self.current_client.selector = query

                if not sel is None and not val is None:
                    self.current_client.filter_attr = sel
                    self.current_client.filter_value = val
                else:
                    self.current_client.filter_attr = None
                    self.current_client.filter_value = None

                self.save()
                return selection

        if not sel is None and not val is None:
            raise InstanceNotFoundError(u"Unable to locate instance for" \
                                " '%s' and filter '%s=%s'" % (query, sel, val))
        else:
            raise InstanceNotFoundError(u"Unable to locate instance for" \
                                                                " '%s'" % query)

    def filter(self, query, sel, val):
        """Main function for filter command

        :param query: query string.
        :type query: str.
        :param sel: the type selection for the select operation.
        :type sel: str.
        :param val: value for the property to be modified.
        :type val: str.
        :returns: returns a list of selected items

        """
        if query:
            if isinstance(query, list):
                if len(query) == 0:
                    raise InstanceNotFoundError(u"Unable to locate instance " \
                                                            "for '%s'" % query)
                else:
                    query = query[0]

            selection = self.get_selection(selector=query, sel=sel, val=val)

            if selection and len(selection) > 0:
                self.current_client.selector = query
                self.current_client.filter_attr = sel
                self.current_client.filter_value = val
                self.save()

            return selection

    def filter_output(self, output, sel, val):
        """Filters a list of dictionaries based on a key:value pair

        :param output: output list.
        :type output: list.
        :param sel: the key for the property to be filtered by.
        :type sel: str.
        :param val: value for the property be filtered by.
        :type val: str.
        :returns: returns an filtered list from output parameter

        """
        newoutput = []
        if isinstance(output, list):
            for entry in output:
                if isinstance(entry, dict):
                    if '/' in sel:
                        sellist = sel.split('/')
                        newentry = copy.copy(entry)

                        for item in sellist:
                            if item in newentry.keys():
                                if item == sellist[-1] and str(newentry[item])\
                                                                        == val:
                                    newoutput.append(entry)
                                else:
                                    newentry = newentry[item]
                    else:
                        if sel in entry.keys() and entry[sel] == val:
                            newoutput.append(entry)
                else:
                    return output

        return newoutput

    def types(self, fulltypes=False):
        """Main function for types command

        :param fulltypes: flag to determine if types return full name.
        :type fulltypes: boolean.
        :returns: returns a list of type strings

        """
        instances = list()
        monolith = self.current_client.monolith
        (founddir, entrytype) = self.check_types_version(monolith)

        if not founddir:
            for ristype in monolith.types:
                if u'Instances' in monolith.types[ristype]:
                    for instance in monolith.types[ristype][u'Instances']:
                        instances.append(instance.type)
        else:
            if u'Instances' in monolith.types[entrytype]:
                for instance in monolith.types[entrytype][u'Instances']:
                    for item in instance.resp.dict["Instances"]:
                        if item and instance._typestring in item.keys() and \
                            not u'ExtendedError' in item[instance._typestring]:
                            if not fulltypes and instance._typestring == \
                                                                u'@odata.type':
                                tval = item[u"@odata.type"].split('#')
                                tval = tval[-1].split('.')[:-1]
                                tval = '.'.join(tval)
                                instances.append(tval)
                            elif item:
                                instances.append(item[instance._typestring])

        return instances

    def gettypeswithetag(self):
        """Supporting function for set and commit command"""
        instancepath = dict()
        instances = dict()
        monolith = self.current_client.monolith

        for ristype in monolith.types:
            if u'Instances' in monolith.types[ristype]:
                for instance in monolith.types[ristype][u'Instances']:
                    instancepath[instance.type] = instance.resp.request.path
                    templist = instance.resp.getheaders()
                    tempindex = [x[0] for x in templist].index('etag')
                    instances[instance.type] = templist[tempindex][1]

        return [instances, instancepath]

    def reloadmonolith(self, path=None):
        """Helper function to reload new data into monolith

        :param path: path to initiate reload monolith from.
        :type path: str.
        :returns: returns True/False depending on if reload occurred

        """
        if path:
            self.current_client.monolith.reload = True
            self.current_client.monolith.load(path=path, skipinit=True, \
                                                                skipcrawl=True)
            self.current_client.monolith.reload = False
            return True
        else:
            return False

    def checkforetagchange(self, instance=None):
        """Function to check the status of the etag

        :param instance: retrieved instance to check etag for change.
        :type instance: dict.

        """
        if instance:
            (oldtag, paths) = self.gettypeswithetag()
            self.reloadmonolith(paths[instance.type])
            (newtag, paths) = self.gettypeswithetag()
            if (oldtag[instance.type] != newtag[instance.type]) and \
                        not self.typepath.defs.hpilodatetimetype in instance.type:
                self.warning_handler("The property you are trying to change " \
                                 "has been updated. Please check entry again " \
                                 " before manipulating it\n")
                raise ValueChangedError()

    def verifyschemasdownloaded(self, monolith):
        """Function to verify that the schema has been downloaded

        :param monolith: full data model retrieved from server.
        :type monolith: dict.

        """
        schemasfound = False
        registriesfound = False

        if monolith.is_redfish:
            schemaid = "/redfish/v1/schemas/?$expand=."
            regid = "/redfish/v1/registries/?$expand=."
        else:
            schemaid = "/rest/v1/schemas"
            regid = "/rest/v1/registries"

        for itemtype in monolith.types:
            if itemtype.startswith("Collection.") and \
                                    u'Instances' in monolith.types[itemtype]:
                for instance in monolith.types[itemtype][u'Instances']:
                    if instance.resp.request.path.lower() == schemaid:
                        schemasfound = True
                    elif instance.resp.request.path.lower() == regid:
                        registriesfound = True

        if not schemasfound:
            self.check_type_and_download(monolith, schemaid, skipcrawl=True)

        if not registriesfound:
            self.check_type_and_download(monolith, regid, skipcrawl=True)

    def check_types_version(self, monolith):
        """Check the types version

        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        :returns: returns boolean based on if resource directory type is in monolith types

        """
        for ristype in monolith.types:
            if self.typepath.defs.resourcedirectorytype.lower() \
                                                in ristype.lower():
                return (True, ristype)

        return (False, None)

    def check_type_and_download(self, monolith, foundhref, skipcrawl=False, \
                                                            loadtype='href'):
        """Check if type exist and download

        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        :param foundhref: href found to be used for comparision.
        :type foundhref: str.
        :param skipcrawl: flag to determine if load should traverse found links.
        :type skipcrawl: boolean.
        :param loadtype: object to determine the type of the structure found.
        :type loadtype: str.

        """
        found = False
        for ristype in monolith.types:
            if u'Instances' in monolith.types[ristype]:
                for instance in monolith.types[ristype][u'Instances']:
                    if foundhref == instance.resp.request.path:
                        found = True
                        break
                    elif foundhref == instance.resp.request.path + '/':
                        found = True
                        break

                if found:
                    break

        if not found:
            try:
                monolith.load(path=foundhref, skipinit=True, \
                      skipcrawl=skipcrawl, includelogs=True, loadtype=loadtype)
            except SessionExpiredRis:
                raise SessionExpired()
            except Exception, excp:
                try:
                    if excp.errno == 10053:
                        raise SessionExpired()
                except:
                    raise excp
                else:
                    raise excp

    def check_types_exists(self, entrytype, currtype, monolith, \
                                                            skipcrawl=False):
        """Check if type exists in current monolith

        :param entrytype: the found entry type.
        :type entrytype: str.
        :param currtype: the current entry type.
        :type currtype: str.
        :param monolith: full data model retrieved from server.
        :type monolith: dict.
        :param skipcrawl: flag to determine if load should traverse found links.
        :type skipcrawl: boolean.

        """
        if u'Instances' in monolith.types[entrytype]:
            for instance in monolith.types[entrytype][u'Instances']:
                try:
                    for item in instance.resp.dict["Instances"]:
                        if item and monolith._typestring in item.keys() and \
                            currtype.lower() in item[monolith._typestring].lower():
                            self.check_type_and_download(monolith, \
                                 item[monolith._hrefstring], skipcrawl=skipcrawl)
                        elif currtype == '"*"':
                            self.check_type_and_download(monolith, \
                                item[monolith._hrefstring], skipcrawl=skipcrawl)
                except:
                    LOGGER.debug(u"Instance error, Instance contents: %s" % \
                                 instance.resp.text)
                    raise

    def get_selection(self, selector=None, sel=None, val=None, setenable=False):
        """Special main function for set/filter with select command

        :param selector: the type selection for the get operation.
        :type selector: str.
        :param sel: property to be modified.
        :type sel: str.
        :param val: value for the property to be modified.
        :type val: str.
        :param setenable: flag to determine if registry should also be returned.
        :type setenable: boolean.
        :returns: returns a list of selected items

        """
        if not sel and not val:
            (sel, val) = self.get_filter_settings()

        attributeregistryfound = dict()
        monolith = self.current_client.monolith

        if selector:
            (founddir, entrytype) = self.check_types_version(monolith)

            if founddir:
                skipcrawl = True
                if selector.lower().startswith("log"):
                    skipcrawl = False
                    self.warning_handler("Full data retrieval enabled. You " \
                                    "may experience longer download times.\n")

                self.check_types_exists(entrytype, selector, monolith, \
                                                            skipcrawl=skipcrawl)

        instances = list()
        if not selector:
            selector = self.current_client.selector

        if not selector:
            if setenable:
                return instances, attributeregistryfound
            else:
                return instances

        xpath = None
        odata = ''

        if not selector == '"*"':
            qvars = self._parse_query(selector)
            qinstance = qvars[u'instance']
            xpath = qvars[u'xpath']
        else:
            qinstance = selector

        for ristype in monolith.types:
            if u'Instances' in monolith.types[ristype]:
                for instance in monolith.types[ristype][u'Instances']:
                    try:
                        odata = instance.resp.dict[u'@odata.type'].lower()
                    except Exception:
                        odata = ''

                    if qinstance.lower() in instance.type.lower() \
                            or qinstance == '"*"' or qinstance.lower() in odata:
                        if setenable:
                            try:
                                if instance.resp.obj["AttributeRegistry"]:
                                    attributeregistryfound[instance.type] = \
                                        instance.resp.obj["AttributeRegistry"]
                            except Exception:
                                pass

                            if self.get_save_helper(instance.resp.request.path,\
                                        monolith.types[ristype][u'Instances']):
                                continue

                        if not sel is None and not val is None:
                            currdict = instance.resp.dict

                            try:
                                if not "/" in sel:
                                    if val[-1] == "*":
                                        if not val[:-1] in str(currdict[sel]):
                                            continue
                                    else:
                                        if not str(currdict[sel]).\
                                                                startswith(val):
                                            continue
                                else:
                                    newargs = sel.split("/")
                                    content = copy.deepcopy(currdict)

                                    if self.filterworkerfunction(workdict=\
                                                content, sel=sel, val=val, \
                                                newargs=newargs, loopcount=0):
                                        instances.append(instance)
                                    continue
                            except Exception:
                                continue

                        if xpath:
                            raise RuntimeError(u"Not implemented")
                        else:
                            instances.append(instance)

        if setenable:
            return instances, attributeregistryfound
        else:
            return instances

    def filterworkerfunction(self, workdict=None, sel=None, val=None, \
                                                    newargs=None, loopcount=0):
        """Helper function for filter application

        :param workdict: working copy of current dictionary.
        :type workdict: dict.
        :param sel: property to be modified.
        :type sel: str.
        :param val: value for the property to be modified.
        :type val: str.
        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :param loopcount: loop count tracker.
        :type loopcount: int.
        :returns: returns boolean based on val parameter being found in newargs

        """
        if workdict and sel and val and newargs:
            if isinstance(workdict, list):
                for item in workdict:
                    if self.filterworkerfunction(workdict=item, sel=sel, \
                                 val=val, newargs=newargs, loopcount=loopcount):
                        return True

                return False

            keys = workdict.keys()
            keyslow = [x.lower() for x in keys]

            if newargs[loopcount].lower() in keyslow:
                if loopcount == (len(newargs) - 1):
                    if val == str(workdict[newargs[loopcount]]):
                        return True

                    return False

                if not (isinstance(workdict[newargs[loopcount]], list) or \
                                isinstance(workdict[newargs[loopcount]], dict)):
                    return False

                workdict = workdict[newargs[loopcount]]
                loopcount += 1

                if self.filterworkerfunction(workdict=workdict, sel=sel, \
                                 val=val, newargs=newargs, loopcount=loopcount):
                    return True

        return False

    def get_commit_selection(self):
        """Special main function for commit command"""
        instances = list()
        monolith = self.current_client.monolith

        for ristype in monolith.types:
            if u'Instances' in monolith.types[ristype]:
                for instance in monolith.types[ristype][u'Instances']:
                    instances.append(instance)

        return instances

    def get_save_header(self, selector=None):
        """Special function for save file headers

        :param selector: the type selection for the get save operation.
        :type selector: str.
        :returns: returns an header ordered dictionary

        """
        instances = OrderedDict()
        monolith = self.current_client.monolith

        if not selector:
            selector = self.current_client.selector

        if not selector:
            return instances

        instances["Comments"] = OrderedDict()

        (founddir, entrytype) = self.check_types_version(\
                                                 self.current_client.monolith)

        if founddir:
            self.check_types_exists(entrytype, "ComputerSystem.", \
                                self.current_client.monolith, skipcrawl=True)

        for ristype in monolith.types:
            if u'Instances' in monolith.types[ristype]:
                for instance in monolith.types[ristype][u'Instances']:
                    if "computersystem." in instance.type.lower():
                        try:
                            if instance.resp.obj["Manufacturer"]:
                                instances["Comments"]["Manufacturer"] = \
                                            instance.resp.obj["Manufacturer"]

                            if instance.resp.obj["Model"]:
                                instances["Comments"]["Model"] = \
                                                    instance.resp.obj["Model"]

                            if instance.resp.obj["Oem"][self.typepath.\
                                                defs.oemhp]["Bios"]["Current"]:
                                oemjson = instance.resp.obj["Oem"]\
                                    [self.typepath.defs.oemhp]["Bios"]["Current"]
                                instances["Comments"]["BIOSFamily"] = \
                                                            oemjson["Family"]
                                instances["Comments"]["BIOSDate"] = \
                                                                oemjson["Date"]
                        except Exception:
                            pass

        return instances

    def get_selector(self):
        """Helper function to return current select option"""
        if self.current_client:
            if self.current_client.selector:
                return self.current_client.selector

        return None

    def get_filter_settings(self):
        """Helper function to return current select option"""
        if self.current_client:
            if not self.current_client.filter_attr is None and not \
                                    self.current_client.filter_value is None:
                return (self.current_client.filter_attr, \
                                            self.current_client.filter_value)

        return (None, None)

    def erase_filter_settings(self):
        """Helper function to return current select option"""
        if self.current_client:
            if not self.current_client.filter_attr is None or \
                                not self.current_client.filter_value is None:
                self.current_client.filter_attr = None
                self.current_client.filter_value = None

    def update_bios_password(self, value):
        """Helper function to return current select option

        :param value: value to be set as the new BIOS password.
        :type value: str.

        """
        if self.current_client:
            self.current_client.bios_password = value

    def get_validation_manager(self, iloversion):
        """Get validation manager helper

        :param iloversion: current systems iLO versions.
        :type iloversion: str.
        :returns: returns a ValidationManager

        """

        if self._validationmanager:
            self._validationmanager._errors = list()
            return self._validationmanager

        monolith = None

        if float(iloversion) >= 4.210:
            monolith = self.current_client.monolith

        (romfamily, biosversion) = self.getbiosfamilyandversion()
        validation_manager = ValidationManager(\
                            local_path=self._config.get_schemadir(), \
                            bios_local_path=self._config.get_biosschemadir(), \
                            romfamily=romfamily, biosversion=biosversion, \
                            iloversion=iloversion, monolith=monolith, \
                            defines=self.typepath)
        self._validationmanager = validation_manager

        return validation_manager

    def remove_readonly(self, body):
        """Removes all readonly items from a dictionary

        :param body: the body to the sent.
        :type body: str.
        :returns: returns dictionary with readonly items removed

        """
        biosmode = False
        iloversion = self.getiloversion()
        type_str = self.current_client.monolith._typestring
        isredfish = self.current_client.monolith.is_redfish

        (_, attributeregistry) = self.get_selection(selector= body[type_str], \
                                                                setenable=True)
        validation_manager = self.get_validation_manager(iloversion)

        schematype = body[type_str]

        try:
            regtype = attributeregistry[body[type_str]]
        except Exception:
            pass

        try:
            if attributeregistry[body[type_str]]:
                biosmode = True
                regfound = validation_manager.find_bios_registry(regtype)
                biosschemafound = validation_manager.find_schema(schematype)

                if isredfish and not isinstance(biosschemafound, RepoRegistryEntry):
                    regfound = self.get_handler(regfound[u'@odata.id'], \
                                verbose=False, service=True, silent=True).obj
                    regfound = RepoRegistryEntry(regfound)
        except Exception:
            regfound = validation_manager.find_schema(schematype)

        if isredfish and not isinstance(regfound, RepoRegistryEntry):
            regfound = self.get_handler(regfound[u'@odata.id'], \
                                verbose=False, service=True, silent=True).obj
            regfound = RepoRegistryEntry(regfound)
        if not regfound:
            LOGGER.warn(u"Unable to locate registry/schema for '%s'", \
                                                                body[type_str])
            return None, None, None
        elif float(iloversion) >= 4.210:
            try:
                locationdict = self.geturidict(regfound.Location[0])
                self.check_type_and_download(self.current_client.monolith, \
                                        locationdict, \
                                        skipcrawl=True, loadtype='ref')
            except Exception, excp:
                raise excp

        if biosmode:
            if float(iloversion) >= 4.210:
                model = regfound.get_registry_model_bios_version(\
                        currdict=body, monolith=self.current_client.monolith)
        elif float(iloversion) >= 4.210:
            model = regfound.get_registry_model(currdict=body, \
                                        monolith=self.current_client.monolith)

        if model and biosmode:
            outdict = self.remove_readonly_helper_bios(body, model)
        elif model:
            outdict = self.remove_readonly_helper(body, model)

        return outdict

    def remove_readonly_helper_bios(self, body, model):
        """Helper function for remove readonly function for gen10 BIOS

        :param body: the body to the sent.
        :type body: str.
        :param model: model for the current type.
        :type model: str.
        :returns: returns body with read only items removed

        """
        if 'Attributes' in body:
            bodykeys = body['Attributes'].keys()
        else:
            bodykeys = body.keys()

        templist = ["Name", "Modified", "Type", "Description", \
                    "AttributeRegistry", "links", "SettingsResult", "Status", \
                    "@odata.context", "@odata.type"]

        for item in model['Attributes']:
            if item['AttributeName'] in bodykeys:
                try:
                    if item['ReadOnly']:
                        templist.append(item['AttributeName'])
                    elif item['IsSystemUniqueProperty']:
                        templist.append(item['AttributeName'])
                except:
                    continue

        if templist:
            for key in templist:
                if key in bodykeys:
                    if 'Attributes' in body:
                        body['Attributes'].pop(key)
                    else:
                        body.pop(key)
                elif key in body.keys():
                    body.pop(key)

        return body

    def remove_readonly_helper(self, body, model):
        """Helper function for remove readonly function for gen10 iLO and others

        :param body: the body to the sent.
        :type body: str.
        :param model: model for the current type.
        :type model: str.
        :returns: returns body with readonly removed

        """
        templist = []

        for key in model.keys():
            readonly = True
            try:
                if isinstance(model[key], dict):
                    try:
                        readonly = model[key].readonly
                        if readonly:
                            templist.append(key)
                            continue
                    except:
                        pass

                    if 'properties' in model[key].keys():
                        if key in body.keys():
                            newdict = self.remove_readonly_helper(body[key], \
                                                    model[key]['properties'])

                            if newdict:
                                body[key] = newdict
                            else:
                                del body[key]

                    elif 'items' in model[key].keys():
                        try:
                            if model[key]['items'].readonly:
                                templist.append(key)
                        except:
                            pass
                        if key in body.keys():
                            if isinstance(body[key], list):
                                for item in body[key]:
                                    self.remove_readonly_helper(item, \
                                            model[key]['items']['properties'])
                    elif readonly:
                        templist.append(key)
            except:
                continue

        if templist:
            for key in templist:
                if key in body.keys():
                    body.pop(key)

        return body

    def get_model(self, currdict, validation_manager, instance, \
                  iloversion, attributeregistry, latestschema=None, \
                  newarg=None, autotest=False):
        """Returns the model for the current instance's schema/registry

        :param currdict: current selection dictionary.
        :type currdict: dict.
        :param validation_manager: validation manager object.
        :type validation_manager: validation object.
        :param instances: current retrieved instances.
        :type instances: dict.
        :param iloversion: current systems iLO versions.
        :type iloversion: str.
        :param attributeregistry: current systems attribute registry.
        :type attributeregistry: dict.
        :param latestschema: flag to determine if we should use smart schema.
        :type latestschema: boolean.
        :param newargs: list of multi level properties to be modified.
        :type newargs: list.
        :param autotest: flag to determine if this part of automatic testing.
        :type autotest: boolean.
        :returns: returns model model, biosmode, bios model

        """
        biosschemafound = None
        bsmodel = None
        biosmode = False
        type_str = self.current_client.monolith._typestring
        isredfish = self.current_client.monolith.is_redfish

        if latestschema:
            schematype, regtype = self.latestschemahelper(currdict, \
                                                          validation_manager)

            if autotest and not isredfish:
                try:
                    if not regtype == attributeregistry[instance.type]:
                        self.warning_handler("Using latest registry.\nFound: " \
                                            "%s\nUsing: %s\n" % \
                                            (attributeregistry[instance.type], \
                                             regtype))
                except Exception:
                    if not schematype == currdict[type_str]:
                        self.warning_handler("Using latest schema.\nFound: " \
                                             "%s\nUsing: %s\n" % \
                                            (currdict[type_str], \
                                             schematype))
        else:
            schematype = currdict[type_str]
            try:
                regtype = attributeregistry[instance.type]
            except Exception:
                pass
        try:
            if attributeregistry[instance.type]:
                regfound = validation_manager.find_bios_registry(regtype)
                biosmode = True
                biosschemafound = validation_manager.find_schema(schematype)

                if biosschemafound and isredfish and not \
                                isinstance(biosschemafound, RepoRegistryEntry):
                    biosschemafound = self.get_handler(biosschemafound[u'@odata.id'], \
                                verbose=False, service=True, silent=True).obj
                    biosschemafound = RepoRegistryEntry(biosschemafound)

        except Exception:
            regfound = validation_manager.find_schema(schematype)

        if regfound and isredfish and not isinstance(regfound, RepoRegistryEntry):
            regfound = self.get_handler(regfound[u'@odata.id'], \
                                verbose=False, service=True, silent=True).obj
            regfound = RepoRegistryEntry(regfound)

        if not regfound:
            LOGGER.warn(u"Unable to locate registry/schema for '%s'", \
                                                            currdict[type_str])
            return None, None, None
        elif float(iloversion) >= 4.210:
            try:
                locationdict = self.geturidict(regfound.Location[0])
                self.check_type_and_download(self.current_client.monolith, \
                                locationdict, skipcrawl=True, loadtype='ref')

                if biosschemafound:
                    locationdict = self.geturidict(biosschemafound.Location[0])
                    self.check_type_and_download(self.current_client.monolith, \
                                 locationdict, skipcrawl=True, loadtype='ref')
            except Exception, excp:
                raise excp

        if biosmode:
            if float(iloversion) >= 4.210:
                model = regfound.get_registry_model_bios_version(\
                    currdict=currdict, monolith=self.current_client.monolith)

            if biosschemafound:
                bsmodel = biosschemafound.get_registry_model(\
                    currdict=currdict, monolith=self.current_client.monolith, \
                    latestschema=latestschema)
            if not biosschemafound and not model:
                model = regfound.get_registry_model_bios_version(currdict)
        else:
            if float(iloversion) >= 4.210:
                model = regfound.get_registry_model(currdict=currdict, \
                                    monolith=self.current_client.monolith, \
                                    newarg=newarg, latestschema=latestschema)
            else:
                model = regfound.get_registry_model(currdict)

        return model, biosmode, bsmodel

    def geturidict(self, locationobj):
        """Return the external reference link.

        :param locationobj: location of the dict
        :type locationobj: dict
        """
        if self.typepath.defs.isgen10:
            try:
                return locationobj["Uri"]
            except Exception:
                raise InvalidPathError("Error accessing Uri path!/n")
        elif self.typepath.defs.isgen9:
            try:
                return locationobj["Uri"]["extref"]
            except Exception:
                raise InvalidPathError("Error accessing extref path!/n")

    def getgen(self, url=None):
        """Updates the defines object based on the iLO manager version"""
        if self.typepath.adminpriv==False and url.startswith("blob"):
            raise UserNotAdminError("")
        self.typepath.getgen(url=url, logger=LOGGER)

    def updatedefinesflag(self, redfishflag=None):
        """Updates the redfish and rest flag depending on system and
        user input

        :param redfishflag: flags if redfish is used
        :type redfishflag: bool
        :returns: boolean; is_redfish or redfishflag

        """
        if self.typepath.defs:
            is_redfish = redfishflag or self.typepath.defs.isgen10
            self.typepath.defs.flagforrest = not is_redfish
            if is_redfish:
                self.typepath.defs.redfishchange()

            return is_redfish
        else:
            return redfishflag

    #TODO: need to see if we do have a dependency on the verbose flag here
    def checkpostpatch(self, body=None, path=None, verbose=False, \
                        service=False, url=None, sessionid=None, headers=None, \
                        iloresponse=False, silent=False, patch=False):
        """Make the post file compatible with the system generation

        :param body: contents to be checked
        :type body: str.
        :param path: The URL location to check
        :type path: str.
        :param verbose: flag to determine additional output.
        :type verbose: boolean.
        :param service: flag to determine if minimum calls should be done.
        :type service: boolean.
        :param url: originating url.
        :type url: str.
        :param sessionid: session id to be used instead of iLO credentials.
        :type sessionid: str.
        :param headers: additional headers to be added to the request.
        :type headers: str.
        :param iloresponse: flag to return the iLO response.
        :type iloresponse: str.
        :param silent: flag to determine if no output should be done.
        :type silent: boolean.
        :param patch: flag to determine if a patch is being made
        :type patch: boolean.
        :returns: modified body and path parameter for target and action respectively

        """
        try:
            if self.typepath.defs.flagforrest:
                if u"Target" not in body and not patch:
                    if u"/Oem/Hp" in path:
                        body[u"Target"] = self.typepath.defs.oempath

                if path.startswith(u"/redfish/v1"):
                    path = path.replace(u"/redfish", u"/rest", 1)

                if u"/Actions/" in path:
                    ind = path.find(u"/Actions/")
                    path = path[:ind]
            elif path.startswith(u"/rest/") and self.typepath.defs.isgen9:
                results = self.get_handler(put_path=path, service=service, \
                              url=url, sessionid=sessionid, headers=headers, \
                              response=iloresponse, silent=silent)
                if results and results.status == 200:
                    if results.dict:
                        if u"Target" in body:
                            actions = results.dict[u"Oem"][self.typepath.defs.\
                                                            oemhp][u"Actions"]
                        elif u"Actions" in body:
                            actions = results.dict[u"Actions"]
                        else:
                            return (path, body)

                    allkeys = actions.keys()
                    targetkey = [x for x in allkeys if x.endswith(body\
                                                                  [u"Action"])]

                    if targetkey[0].startswith(u"#"):
                        targetkey[0] = targetkey[0][1:]

                path = path.replace(u"/rest", u"/redfish", 1)
                path = path+u"/Actions"

                if u"Target" in body:
                    path = path+self.typepath.defs.oempath
                    del body["Target"]

                if targetkey:
                    path = path + u"/" + targetkey[0] + u"/"

            return (path, body)
        except Exception as excp:
            raise excp

    def checkselectforgen(self, query):
        """Changes the query to match the Generation's HP string.

        :param query: query to be changed to match Generation's HP string
        :type query: str
        :returns: returns a modified query matching the Generation's HP string.

        """
        query = query.lower()
        returnval = query

        if self.typepath.defs.isgen9:
            if query.startswith((u"hpeeskm", u"#hpeeskm")) or \
                                    query.startswith((u"hpeskm", u"#hpeskm")):
                returnval = self.typepath.defs.hpeskmtype
            elif u'bios.' in query[:9].lower():
                returnval = self.typepath.defs.biostype
            elif query.startswith((u"hpe", u"#hpe")):
                returnval = query[:4].replace(u"hpe", u"hp")+query[4:]
        else:
            if query.startswith((u"hpeskm", u"#hpeskm")) or \
                                    query.startswith((u"hpeeskm", u"#hpeeskm")):
                returnval = self.typepath.defs.hpeskmtype
            elif u'bios.' in query[:9].lower():
                returnval = self.typepath.defs.biostype
            elif not query.startswith((u"hpe", u"#hpe")):
                returnval = query[:3].replace(u"hp", u"hpe")+query[3:]

        return returnval

    def latestschemahelper(self, currdict, validation_manager):
        """Finds the latestschema for a dictionary.

        :param currdict: dictionary of type to check for schema
        :type currdict: dict
        :param validation_manager: validation manager object.
        :type validation_manager: validation object.
        :returns: returns the schematype and regtype found for the dict.

        """
        type_str = self.current_client.monolith._typestring
        isredfish = self.current_client.monolith.is_redfish
        href_str = self.current_client.monolith._hrefstring

        schematype = currdict[type_str].split('.')[0] + '.'

        if isredfish:
            schematype = schematype[1:-1]

            reglist = validation_manager._classes_registry[0][u'Members']
            regs = [x[href_str] for x in reglist if\
                    'biosattributeregistry' in x[href_str].lower()]
            i = [reglist.index(x) for x in reglist if \
                            'biosattributeregistry' in x[href_str].lower()]
            regs = zip(regs, i)
        else:
            reglist = validation_manager._classes_registry[0][u'Items']

            for item in validation_manager._classes[0][u'Items']:
                if item and item[u'Schema'].startswith(schematype):
                    schematype = item[u'Schema']
                    break

            regs = [x[u'Schema'] for x in reglist if x[u'Schema']\
                    .lower().startswith('hpbiosattributeregistry')]
            i = [reglist.index(x) for x in reglist if x[u'Schema']\
                 .lower().startswith('hpbiosattributeregistry')]
            regs = zip(regs, i)

        for item in sorted(regs, reverse=True):
            if isredfish:
                reg = self.get_handler(reglist[item[1]][href_str], \
                            verbose=False, service=True, silent=True).dict
            else:
                reg = reglist[item[1]]
            locationdict = self.geturidict(reg[u'Location'][0])
            extref = self.get_handler(locationdict, verbose=False, \
                                                service=True, silent=True)

            if extref:
                if isredfish:
                    regtype = item[0].split('/')
                    regtype = regtype[len(regtype)-2]
                else:
                    regtype = item[0]
                break
        return schematype, regtype
