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
import json
from restobject import RestObject

def ex20_get_ilo_nic(restobj, get_active):
    sys.stdout.write("\nEXAMPLE 20: Get iLO's NIC configuration\n")
    instances = restobj.search_for_type("Manager.")

    for instance in instances:
        tmp = restobj.rest_get(instance["href"])  
        response = restobj.rest_get(tmp.dict["links"]["EthernetNICs"]["href"])

        for nic in response.dict["Items"]:
            if get_active and nic["Status"]["State"] == "Enabled":
                sys.stdout.write("Active\t" + nic["links"]["self"]["href"] + \
                                                ": " + json.dumps(nic) + "\n")
            elif get_active == False and nic["Status"]["State"] == "Disabled":
                sys.stdout.write("InActive\t" + nic["links"]["self"]["href"] + \
                                                ": " + json.dumps(nic) + "\n")

if __name__ == "__main__":
    # When running on the server locally use the following commented values
    # iLO_host = "blobstore://."
    # iLO_account = "None"
    # iLO_password = "None"

    # When running remotely connect using the iLO address, iLO account name, 
    # and password to send https requests
    iLO_host = "https://16.83.63.43"
    iLO_account = "admin"
    iLO_password = "password"
    
    #Create a REST object
    REST_OBJ = RestObject(iLO_host, iLO_account, iLO_password)
    ex20_get_ilo_nic(REST_OBJ, True)
