# Copyright 2016 Hewlett Packard Enterprise Development, LP.
 #
 # Licensed under the Apache License, Version 2.0 (the "License"); you may
 # not use this file except in compliance with the License. You may obtain
 # a copy of the License at
 #
 #      http://www.apache.org/licenses/LICENSE-2.0
 #
 # Unless required by applicable law or agreed to in writing, software
 # distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 # WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 # License for the specific language governing permissions and limitations
 # under the License.

import sys
from _restobject import RestObject

def ex37_set_ESKM_PrimaryKeyServer(restobj, PrimaryKeyServerAddress,\
                               PrimaryKeyServerPort):
    sys.stdout.write("\nEXAMPLE 37: Set ESKM Primary Key Server\n")
    instances = restobj.search_for_type("ESKM.")

    for instance in instances:
        body = dict()

        body["PrimaryKeyServerAddress"] = PrimaryKeyServerAddress
        body["PrimaryKeyServerPort"] = int(PrimaryKeyServerPort)

        response = restobj.rest_patch(instance["href"], body)
        restobj.error_handler(response)

if __name__ == "__main__":
    # When running on the server locally use the following commented values
    # iLO_https_url = "blobstore://."
    # iLO_account = "None"
    # iLO_password = "None"

    # When running remotely connect using the iLO secured (https://) address, 
    # iLO account name, and password to send https requests
    # iLO_https_url acceptable examples:
    # "https://10.0.0.100"
    # "https://f250asha.americas.hpqcorp.net"
    iLO_https_url = "https://10.0.0.100"
    iLO_account =  "admin"
    iLO_password =  "password"
    PrimaryKeyServerAddress =  "10.0.0.100"
    PrimaryKeyServerPort =  "9000"
    
    # Create a REST object
    REST_OBJ = RestObject(iLO_https_url, iLO_account, iLO_password)
    ex37_set_ESKM_PrimaryKeyServer(REST_OBJ, PrimaryKeyServerAddress,\
                               PrimaryKeyServerPort)