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
""" Shared types used in this module """

#---------Imports---------

import logging
import jsonpatch
from ilorest.rest.v1_helper import JSONEncoder

#---------End of imports---------

#---------Debug logger---------

LOGGER = logging.getLogger(__name__)

#---------End of debug logger---------

class JSONEncoder(JSONEncoder):
    """Custom JSONEncoder that understands our types"""
    def default(self, obj):
        """Set defaults

		:param obj: json object.
        :type obj: str.

		"""
        if isinstance(obj, Dictable):
            return obj.to_dict()
        elif isinstance(obj, jsonpatch.JsonPatch):
            return obj.patch
        return super(JSONEncoder, self).default(obj)

class Dictable(object):
    """A base class which adds the to_dict method used during json encoding"""
    def to_dict(self):
        """Overridable funciton"""
        raise RuntimeError("You must override this method in your derived" \
                                                                    " class")

