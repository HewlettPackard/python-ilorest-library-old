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
"""RIS implementation"""

#---------Imports---------

import re
import sys
import json
import logging
import threading
import urlparse2 #pylint warning disable
from Queue import Queue
from collections import (OrderedDict)

import jsonpath_rw
import jsonpointer
from jsonpointer import set_pointer
import redfish.rest.v1

from redfish.ris.sharedtypes import Dictable

#---------End of imports---------

#---------Debug logger---------

LOGGER = logging.getLogger(__name__)

#---------End of debug logger---------

class BiosUnregisteredError(Exception):
    """Raised when BIOS has not been registered correctly in iLO"""
    pass

class SessionExpiredRis(Exception):
    """Raised when session has expired"""
    pass

class RisMonolithMemberBase(Dictable):
    """RIS monolith member base class"""
    pass

class RisMonolithMemberv100(RisMonolithMemberBase):
    """Wrapper around RestResponse that adds the monolith data"""
    def __init__(self, restresp, isredfish):
        self._resp = restresp
        self._patches = list()
        self._type = None
        if isredfish:
            self._typestring = u'@odata.type'
        else:
            self._typestring = u'Type'

    def _get_type(self):
        """Return type from monolith"""
        if self._typestring in self._resp.dict:
            return self._resp.dict[self._typestring]
        elif u'type' in self._resp.dict:
            return self._resp.dict[u'type']
        return None
    type = property(_get_type, None)

    def _get_maj_type(self):
        """Return maj type from monolith"""
        if self.type:
            return self.type[:-4]
        return None
    maj_type = property(_get_maj_type, None)

    def _get_resp(self):
        """Return resp from monolith"""
        return self._resp
    resp = property(_get_resp, None)

    def _get_patches(self):
        """Return patches from monolith"""
        return self._patches
    patches = property(_get_patches, None)

    def to_dict(self):
        """Convert monolith to dict"""
        result = OrderedDict()
        if self.type:
            result[u'Type'] = self.type

            if self.maj_type == u'Collection.1' and \
                                            u'MemberType' in self._resp.dict:
                result[u'MemberType'] = self._resp.dict[u'MemberType']

            result[u'links'] = OrderedDict()
            result[u'links'][u'href'] = ''
            headers = dict()

            for header in self._resp.getheaders():
                headers[header[0]] = header[1]

            result[u'Headers'] = headers

            if 'etag' in headers:
                result[u'ETag'] = headers['etag']

            result[u'OriginalUri'] = self._resp.request.path
            result[u'Content'] = self._resp.dict
            result[u'Patches'] = self._patches

        return result

    def load_from_dict(self, src):
        """Load variables from dict monolith

        :param src: source to load from
        :type src: dict

        """
        if u'Type' in src:
            self._type = src[u'Type']
            restreq = redfish.rest.v1.RestRequest(method='GET', \
                                                    path=src[u'OriginalUri'])

            src['restreq'] = restreq
            self._resp = redfish.rest.v1.StaticRestResponse(**src)
            self._patches = src[u'Patches']

    def _reducer(self, indict, breadcrumbs=None, outdict=OrderedDict()):
        """Monolith reducer

        :param indict: input dictionary.
        :type indict: dict.
        :param breadcrumbs: breadcrumbs from previous operations.
        :type breadcrumbs: dict.
        :param outdict: expected output format.
        :type outdict: dictionary type.
        :returns: returns outdict

        """
        if breadcrumbs is None:
            breadcrumbs = []

        if isinstance(indict, dict):
            for key, val in indict.items():
                breadcrumbs.append(key) # push

                if isinstance(val, dict):
                    self._reducer(val, breadcrumbs, outdict)
                elif isinstance(val, list) or isinstance(val, tuple):
                    for i in range(0, len(val)):
                        breadcrumbs.append(u'%s' % i) # push
                        self._reducer(val[i], breadcrumbs, outdict)

                        del breadcrumbs[-1] # pop
                elif isinstance(val, tuple):
                    self._reducer(val, breadcrumbs, outdict)
                else:
                    self._reducer(val, breadcrumbs, outdict)

                del breadcrumbs[-1] # pop
        else:
            outkey = '/'.join(breadcrumbs)
            outdict[outkey] = indict

        return outdict

    def _jsonpath_reducer(self, indict, breadcrumbs=None, \
                                                        outdict=OrderedDict()):
        """JSON Path Reducer

        :param indict: input dictionary.
        :type indict: dict.
        :param breadcrumbs: breadcrumbs from previous operations.
        :type breadcrumbs: dict.
        :param outdict: expected output format.
        :type outdict: dictionary type.
        :returns: returns outdict

        """
        if breadcrumbs is None:
            breadcrumbs = []

        if isinstance(indict, dict):
            for key, val in indict.items():
                breadcrumbs.append(key) # push

                if isinstance(val, dict):
                    self._reducer(val, breadcrumbs, outdict)
                elif isinstance(val, list) or isinstance(val, tuple):
                    for i in range(0, len(val)):
                        breadcrumbs.append(u'[%s]' % i) # push
                        self._reducer(val[i], breadcrumbs, outdict)

                        del breadcrumbs[-1] # pop
                elif isinstance(val, tuple):
                    self._reducer(val, breadcrumbs, outdict)
                else:
                    self._reducer(val, breadcrumbs, outdict)

                del breadcrumbs[-1] # pop
        else:
            outkey = '.'.join(breadcrumbs)
            outkey = outkey.replace(u'.[', u'[')
            outdict[outkey] = indict

        return outdict

    def reduce(self):
        """Returns a "flatten" dict with nested data represented in
        JSONpath notation"""
        result = OrderedDict()

        if self.type:
            result[u'Type'] = self.type

            if self.maj_type == u'Collection.1' and \
                                            u'MemberType' in self._resp.dict:
                result[u'MemberType'] = self._resp.dict[u'MemberType']

            self._reducer(self._resp.dict)
            result[u'OriginalUri'] = self._resp.request.path
            result[u'Content'] = self._reducer(self._resp.dict)

        return result

class RisMonolithv100(Dictable):
    """Monolithic cache of RIS data"""
    def __init__(self, client):
        """Initialize RisMonolith

        :param client: client to utilize
        :type client: RmcClient object

        """
        self._client = client
        self.name = u"Monolithic output of RIS Service"
        self.types = OrderedDict()
        self._visited_urls = list()
        self._current_location = '/' # "root"
        self.queue = Queue()
        self._type = None
        self._name = None
        self.progress = 0
        self.reload = False
        self.is_redfish = client._rest_client.is_redfish

        if self.is_redfish:
            self._resourcedir = '/redfish/v1/ResourceDirectory/'
            self._typestring = u'@odata.type'
            self._hrefstring = u'@odata.id'
        else:
            self._resourcedir = '/rest/v1/ResourceDirectory'
            self._typestring = u'Type'
            self._hrefstring = u'href'

    def _get_type(self):
        """Return monolith version type"""
        return u"Monolith.1.0.0"

    type = property(_get_type, None)

    def update_progress(self):
        """Simple function to increment the dot progress"""
        if self.progress % 6 == 0:
            sys.stdout.write('.')

    def get_visited_urls(self):
        """Return the visited URLS"""
        return self._visited_urls

    def set_visited_urls(self, visited_urls):
        """Set visited URLS to given list."""
        self._visited_urls = visited_urls

    def load(self, path=None, includelogs=False, skipinit=False, \
                        skipcrawl=False, loadtype='href', loadcomplete=False):
        """Walk entire RIS model and cache all responses in self.

        :param path: path to start load from.
        :type path: str.
        :param includelogs: flag to determine if logs should be downloaded also.
        :type includelogs: boolean.
        :param skipinit: flag to determine if first run of load.
        :type skipinit: boolean.
        :param skipcrawl: flag to determine if load should traverse found links.
        :type skipcrawl: boolean.
        :param loadtype: flag to determine if load is meant for only href items.
        :type loadtype: str.
        :param loadcomplete: flag to download the entire monolith
        :type loadcomplete: boolean

        """
        if not skipinit:
            if LOGGER.getEffectiveLevel() == 40:
                sys.stdout.write("Discovering data...")
            else:
                LOGGER.warning("Discovering data...")
            self.name = self.name + u' at %s' % self._client.base_url

            if not self.types:
                self.types = OrderedDict()

        if not threading.active_count() >= 6:
            for _ in range(5):
                workhand = SuperDuperWorker(self.queue)
                workhand.setDaemon(True)
                workhand.start()

        selectivepath = path
        if not selectivepath:
            selectivepath = self._client._rest_client.default_prefix

        self._load(selectivepath, skipcrawl=skipcrawl, includelogs=includelogs,\
             skipinit=skipinit, loadtype=loadtype, loadcomplete=loadcomplete)
        self.queue.join()

        if not skipinit:
            if LOGGER.getEffectiveLevel() == 40:
                sys.stdout.write("Done\n")
            else:
                LOGGER.warning("Done\n")

    def _load(self, path, skipcrawl=False, originaluri=None, includelogs=False,\
                        skipinit=False, loadtype='href', loadcomplete=False):
        """Helper function to main load function.

        :param path: path to start load from.
        :type path: str.
        :param skipcrawl: flag to determine if load should traverse found links.
        :type skipcrawl: boolean.
        :param originaluri: variable to assist in determining originating path.
        :type originaluri: str.
        :param includelogs: flag to determine if logs should be downloaded also.
        :type includelogs: boolean.
        :param skipinit: flag to determine if first run of load.
        :type skipinit: boolean.
        :param loadtype: flag to determine if load is meant for only href items.
        :type loadtype: str.
        :param loadcomplete: flag to download the entire monolith
        :type loadcomplete: boolean

        """
        if path.endswith("?page=1"):
            return
        elif not includelogs:
            if "/Logs/" in path:
                return

        #TODO: need to find a better way to support non ascii characters
        path = path.replace("|", "%7C")
        #remove fragments
        newpath = urlparse2.urlparse(path)
        newpath.fragment = ''
        path = urlparse2.urlunparse(newpath)

        LOGGER.debug(u'_loading %s', path)

        if not self.reload:
            if path.lower() in self._visited_urls:
                return

        resp = self._client.get(path)

        if resp.status != 200 and path.lower() == self._client.typepath.defs.\
                                                                    biospath:
            raise BiosUnregisteredError()
        elif resp.status != 200:
            path = path + '/'
            resp = self._client.get(path)

            if resp.status == 401:
                raise SessionExpiredRis("Invalid session. Please logout and "\
                                        "log back in or include credentials.")
            elif resp.status != 200:
                return

        if loadtype == "ref":
            self.parse_schema(resp)

        self.queue.put((resp, path, skipinit, self))

        if loadtype == 'href':
            #follow all the href attributes
            if self.is_redfish:
                jsonpath_expr = jsonpath_rw.parse(u"$..'@odata.id'")
            else:
                jsonpath_expr = jsonpath_rw.parse(u'$..href')
            matches = jsonpath_expr.find(resp.dict)

            if 'links' in resp.dict and 'NextPage' in resp.dict['links']:
                if originaluri:
                    next_link_uri = originaluri + '?page=' + \
                                    str(resp.dict['links']['NextPage']['page'])
                    href = u'%s' % next_link_uri

                    self._load(href, originaluri=originaluri, \
                               includelogs=includelogs, skipcrawl=skipcrawl, \
                               skipinit=skipinit)
                else:
                    next_link_uri = path + '?page=' + \
                                    str(resp.dict['links']['NextPage']['page'])

                    href = u'%s' % next_link_uri
                    self._load(href, originaluri=path, includelogs=includelogs,\
                                        skipcrawl=skipcrawl, skipinit=skipinit)

            (newversion, dirmatch) = self.check_for_directory(matches)
            if not newversion and not skipcrawl:
                for match in matches:
                    if path == "/rest/v1":
                        if str(match.full_path) == "links.Schemas.href" or \
                                str(match.full_path) == "links.Registries.href":
                            continue
                    else:
                        if str(match.full_path) == "Registries.@odata.id" or \
                                str(match.full_path) == "JsonSchemas.@odata.id":
                            continue

                    if match.value == path:
                        continue

                    href = u'%s' % match.value
                    self._load(href, skipcrawl=skipcrawl, \
                           originaluri=originaluri, includelogs=includelogs, \
                           skipinit=skipinit)
            elif not skipcrawl:
                href = u'%s' % dirmatch.value
                self._load(href, skipcrawl=skipcrawl, originaluri=originaluri, \
                                    includelogs=includelogs, skipinit=skipinit)
            if loadcomplete:
                for match in matches:
                    self._load(match.value, skipcrawl=skipcrawl, originaluri=\
                       originaluri, includelogs=includelogs, skipinit=skipinit)

    def parse_schema(self, resp):
        """Function to get and replace schema $ref with data

        :param resp: response data containing ref items.
        :type resp: str.

        """
        #pylint: disable=maybe-no-member
        jsonpath_expr = jsonpath_rw.parse(u'$.."$ref"')
        matches = jsonpath_expr.find(resp.dict)
        respcopy = resp.dict
        typeregex = '([#,@].*?\.)'
        if matches:
            for match in matches:
                fullpath = str(match.full_path)
                jsonfile = match.value.split('#')[0]
                jsonpath = match.value.split('#')[1]
                listmatch = None
                found = None

                if 'redfish.dmtf.org' in jsonfile:
                    if 'odata' in jsonfile:
                        jsonpath = jsonpath.replace(jsonpath.split('/')[-1], \
                                            'odata' + jsonpath.split('/')[-1])
                    jsonfile = 'Resource.json'

                found = re.search(typeregex, fullpath)
                if found:
                    repitem = fullpath[found.regs[0][0]:found.regs[0][1]]
                    schemapath = '/' + fullpath.replace(repitem, '~').\
                                        replace('.', '/').replace('~', repitem)
                else:
                    schemapath = '/' + fullpath.replace('.', '/')

                if '.json' in jsonfile:
                    itempath = schemapath

                    if self.is_redfish:
                        if resp.request.path[-1] == '/':
                            newpath = '/'.join(resp.request.path.split('/')\
                                                [:-2]) + '/' + jsonfile + '/'
                        else:
                            newpath = '/'.join(resp.request.path.split('/')\
                                                [:-1]) + '/' + jsonfile + '/'
                    else:
                        newpath = '/'.join(resp.request.path.split('/')[:-1]) \
                                                                + '/' + jsonfile

                    if 'href.json' in newpath:
                        continue

                    if not newpath.lower() in self._visited_urls:
                        self.load(newpath, skipcrawl=True, includelogs=False, \
                                                skipinit=True, loadtype='ref')

                    instance = list()

                    if u'st' in self.types:
                        for stitem in self.types[u'st'][u'Instances']:
                            instance.append(stitem)
                    if u'ob' in self.types:
                        for obitem in self.types[u'ob'][u'Instances']:
                            instance.append(obitem)

                    for item in instance:
                        if jsonfile in item.resp._rest_request._path:
                            if 'anyOf' in fullpath:
                                break

                            dictcopy = item.resp.dict
                            listmatch = re.search('[[][0-9]+[]]', itempath)

                            if listmatch:
                                start = listmatch.regs[0][0]
                                end = listmatch.regs[0][1]

                                newitempath = [itempath[:start], itempath[end:]]
                                start = jsonpointer.JsonPointer(newitempath[0])
                                end = jsonpointer.JsonPointer(newitempath[1])

                                del start.parts[-1], end.parts[-1]
                                vals = start.resolve(respcopy)

                                count = 0

                                for val in vals:
                                    try:
                                        if '$ref' in end.resolve(val).iterkeys():
                                            end.resolve(val).pop('$ref')
                                            end.resolve(val).update(dictcopy)
                                            replace_pointer = jsonpointer.\
                                                JsonPointer(end.path + jsonpath)

                                            data = replace_pointer.resolve(val)
                                            set_pointer(val, end.path, data)
                                            start.resolve(respcopy)[count].\
                                                                    update(val)

                                            break
                                    except:
                                        count += 1
                            else:
                                itempath = jsonpointer.JsonPointer(itempath)
                                del itempath.parts[-1]

                                if '$ref' in itempath.resolve(respcopy).\
                                                                    iterkeys():
                                    itempath.resolve(respcopy).pop('$ref')
                                    itempath.resolve(respcopy).update(dictcopy)

                if jsonpath:
                    if 'anyOf' in fullpath:
                        continue

                    if not jsonfile:
                        replacepath = jsonpointer.JsonPointer(jsonpath)
                        schemapath = schemapath.replace('/$ref', '')
                        schemapath = schemapath.translate(None, '[]')
                        schemapath = jsonpointer.JsonPointer(schemapath)
                        data = replacepath.resolve(respcopy)

                        if '$ref' in schemapath.resolve(respcopy):
                            schemapath.resolve(respcopy).pop('$ref')
                            schemapath.resolve(respcopy).update(data)

                    else:
                        if not listmatch:
                            schemapath = schemapath.replace('/$ref', '')
                            replacepath = schemapath + jsonpath
                            replace_pointer = jsonpointer.\
                                                        JsonPointer(replacepath)
                            data = replace_pointer.resolve(respcopy)
                            set_pointer(respcopy, schemapath, data)

            resp.json(respcopy)
        else:
            resp.json(respcopy)

    def check_for_directory(self, matches):
        """Function to allow checking for new directory

        :param matches: current found matches.
        :type matches: dict.

        """
        for match in matches:
            if match.value == self._resourcedir:
                return (True, match)

        return (False, None)

    def branch_worker(self, resp, path, skipinit):
        """Helper for load function, creates threaded worker

        :param resp: response received.
        :type resp: str.
        :param path: path correlating to the response.
        :type path: str.
        :param skipinit: flag to determine if progress bar should be updated.
        :type skipinit: boolean.

        """
        self._visited_urls.append(path.lower())

        member = RisMonolithMemberv100(resp, self.is_redfish)
        if not member.type:
            return

        self.update_member(member)

        if not skipinit:
            self.progress += 1
            if LOGGER.getEffectiveLevel() == 40:
                self.update_progress()

    def update_member(self, member):
        """Adds member to this monolith. If the member already exists the
        data is updated in place.

        :param member: Ris monolith member object made by branch worker.
        :type member: RisMonolithMemberv100.

        """
        if member.maj_type not in self.types:
            self.types[member.maj_type] = OrderedDict()
            self.types[member.maj_type][u'Instances'] = list()

        found = False

        for indices in xrange(len(self.types[member.maj_type][u'Instances'])):
            inst = self.types[member.maj_type][u'Instances'][indices]

            if inst.resp.request.path == member.resp.request.path:
                self.types[member.maj_type][u'Instances'][indices] = member
                self.types[member.maj_type][u'Instances'][indices].patches.\
                                    extend([patch for patch in inst.patches])

                found = True
                break

        if not found:
            self.types[member.maj_type][u'Instances'].append(member)

    def load_from_dict(self, src):
        """Load data to monolith from dict

        :param src: data receive from rest operation.
        :type src: str.

        """
        self._type = src[u'Type']
        self._name = src[u'Name']
        self.types = OrderedDict()

        for typ in src[u'Types']:
            for inst in typ[u'Instances']:
                member = RisMonolithMemberv100(None, self.is_redfish)
                member.load_from_dict(inst)
                self.update_member(member)

        return

    def to_dict(self):
        """Convert data to monolith from dict"""
        result = OrderedDict()
        result[u'Type'] = self.type
        result[u'Name'] = self.name
        types_list = list()

        for typ in self.types.keys():
            type_entry = OrderedDict()
            type_entry[u'Type'] = typ
            type_entry[u'Instances'] = list()

            for inst in self.types[typ][u'Instances']:
                type_entry[u'Instances'].append(inst.to_dict())

            types_list.append(type_entry)

        result[u'Types'] = types_list
        return result

    def reduce(self):
        """Reduce monolith data"""
        result = OrderedDict()
        result[u'Type'] = self.type
        result[u'Name'] = self.name
        types_list = list()

        for typ in self.types.keys():
            type_entry = OrderedDict()
            type_entry[u'Type'] = typ

            for inst in self.types[typ][u'Instances']:
                type_entry[u'Instances'] = inst.reduce()

            types_list.append(type_entry)

        result[u'Types'] = types_list
        return result

    def _jsonpath2jsonpointer(self, instr):
        """Convert json path to json pointer

        :param instr: input path to be converted to pointer.
        :type instr: str.

        """
        outstr = instr.replace('.[', '[')
        outstr = outstr.replace('[', '/')
        outstr = outstr.replace(']', '/')

        if outstr.endswith('/'):
            outstr = outstr[:-1]

        return outstr

    def _get_current_location(self):
        """Return current location"""
        return self._current_location

    def _set_current_location(self, newval):
        """Set current location"""
        self._current_location = newval

    location = property(_get_current_location, _set_current_location)

    def list(self, lspath=None):
        """Function for list command

        :param lspath: path list.
        :type lspath: list.

        """
        results = list()
        path_parts = [u'Types'] # Types is always assumed

        if isinstance(lspath, list) and len(lspath) > 0:
            lspath = lspath[0]
            path_parts.extend(lspath.split(u'/'))
        elif not lspath:
            lspath = u'/'
        else:
            path_parts.extend(lspath.split(u'/'))

        currpos = self.to_dict()
        for path_part in path_parts:
            if not path_part:
                continue

            if isinstance(currpos, RisMonolithMemberv100):
                break
            elif isinstance(currpos, dict) and path_part in currpos:
                currpos = currpos[path_part]
            elif isinstance(currpos, list):
                for positem in currpos:
                    if u'Type' in positem and path_part == positem[u'Type']:
                        currpos = positem
                        break

        results.append(currpos)

        return results

    def killthreads(self):
        """Function to kill threads on logout"""
        threads = []
        for thread in threading.enumerate():
            if isinstance(thread, SuperDuperWorker):
                self.queue.put(('KILL', 'KILL', 'KILL', 'KILL'))
                threads.append(thread)

        for thread in threads:
            thread.join()

class RisMonolith(RisMonolithv100):
    """Latest implementation of RisMonolith"""
    def __init__(self, client):
        """Initialize Latest RisMonolith

        :param client: client to utilize
        :type client: RmcClient object

        """
        super(RisMonolith, self).__init__(client)

class SuperDuperWorker(threading.Thread):
    """Recursive worker implementation"""
    def __init__(self, queue):
        """Initialize SuperDuperWorker

        :param queue: queue for worker
        :type queue: Queue object

        """
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        """Thread creator"""
        while True:
            (resp, path, skipinit, thobj) = self.queue.get()
            if resp == 'KILL' and path == 'KILL' and skipinit == 'KILL' and\
                                                            thobj == 'KILL':
                break
            thobj.branch_worker(resp, path, skipinit)
            self.queue.task_done()
