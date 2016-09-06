# Copyright 2016 Hewlett Packard Enterprise Development LP
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

def ex1_get_resource_directory(restobj):
    sys.stdout.write("\nEXAMPLE 1: Find the resource directory " + "\n")
    response = restobj.rest_get("/rest/v1/resourcedirectory")
    resources = {}

    if response.status == 200:
        sys.stdout.write("\tFound resource directory at /rest/v1/resource" \
                                                        "directory" + "\n\n")
        for resource in response.dict["Instances"]:
            try:
                sys.stdout.write("\t" + str(resource["Type"]) + "\n\t\t" + \
                             str(resource["href"]) + "\n")
            except KeyError:
                pass
        resources["resources"] = response.dict["Instances"]
        return resources
    else:
        sys.stderr.write("\tResource directory missing at /rest/v1/resource" \
                                                            "directory" + "\n")

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
    iLO_account = "admin"
    iLO_password = "password"
    
    #Create a REST object
    REST_OBJ = RestObject(iLO_https_url, iLO_account, iLO_password)
    ex1_get_resource_directory(REST_OBJ)
