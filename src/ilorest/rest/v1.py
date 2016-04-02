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
"""Module for working with ProLiant REST technology."""

#---------Imports---------

import logging
from ilorest.rest.v1_helper import get_client_instance

#---------End of imports---------


#---------Debug logger---------

LOGGER = logging.getLogger(__name__)

#---------End of debug logger---------

def rest_client(base_url=None, username=None, password=None, \
                                default_prefix='/rest/v1', biospassword=None, \
                                sessionkey=None, is_redfish=False):
    """ An client instance will be returned for RESTful API

    :param base_url: rest host or ip address.
    :type base_url: str.
    :param username: username required to login to server
    :type username: str
    :param password: password credentials required to login
    :type password: str
    :param default_prefix: default root to extract tree
    :type default_prefix: str
    :param biospassword: BIOS password for the server if set
    :type biospassword: str
    :param sessionkey: session key credential for current login
    :type sessionkey: str
    :param is_redfish: boolean to differentiate between rest/v1 and Redfish
    :type is_redfish: boolean
    :returns: a client object for HPE RESTful API

    """
    return get_client_instance(base_url, username, password, default_prefix, \
                                biospassword, sessionkey, is_redfish=is_redfish)

def redfish_client(base_url=None, username=None, password=None, \
                           default_prefix='/redfish/v1/', biospassword=None, \
                           sessionkey=None, is_redfish=True):
    """ An client Instance will be returned for Redfish API. Every request"""
    """ sent by this instance will contain a Redfish specific header (Odata)

    :param base_url: rest host or ip address.
    :type base_url: str.
    :param username: username rquired to login to server
    :type: str
    :param password: password credentials required to login
    :type password: str
    :param default_prefix: default root to extract tree
    :type default_prefix: str
    :param biospassword: BIOS password for the server if set
    :type biospassword: str
    :param sessionkey: session key credential for current login
    :type sessionkey: str
    :param is_redfish: boolean to differentiate between rest/v1 and Redfish
    :type is_redfish: boolean
    :returns: a client object for Redfish API

    """
    return get_client_instance(base_url, username, password, default_prefix, \
                                biospassword, sessionkey, is_redfish=is_redfish)

