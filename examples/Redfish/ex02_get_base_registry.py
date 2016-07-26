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
from _redfishobject import RedfishObject
from ilorest.rest.v1_helper import ServerDownOrUnreachableError

def ex2_get_base_registry(redfishobj):
    sys.stdout.write("\nEXAMPLE 2: Find and return registry " + "\n")
    response = redfishobj.redfish_get("/redfish/v1/Registries/")

    messages = {}
    location = None
    
    for entry in response.dict["Members"]:
        if not [x for x in ["/Base/", "/iLO/"] if x in entry["@odata.id"]]:
            continue
        else:
            registry = redfishobj.redfish_get(entry["@odata.id"])
        
        for location in registry.dict["Location"]:  
            if "extref" in location["Uri"]:
                location = location["Uri"]["extref"]
            else:
                location = location["Uri"]

            reg_resp = redfishobj.redfish_get(location)
            if reg_resp.status == 200:
                sys.stdout.write("\tFound " + reg_resp.dict["RegistryPrefix"] \
                                    + " at " + location + "\n")
                messages[reg_resp.dict["RegistryPrefix"]] = \
                                                    reg_resp.dict["Messages"]
            else:
                sys.stdout.write("\t" + reg_resp.dict["RegistryPrefix"] + \
                                            " not found at " + location + "\n")

    return messages

if __name__ == "__main__":
    # When running on the server locally use the following commented values
    # iLO_host = "blobstore://."
    # iLO_account = "None"
    # iLO_password = "None"

    # When running remotely connect using the iLO address, iLO account name, 
    # and password to send https requests
    iLO_host = "https://10.0.0.100"
    iLO_account = "admin"
    iLO_password = "password"

    # Create a REDFISH object
    try:
        REDFISH_OBJ = RedfishObject(iLO_host, iLO_account, iLO_password)
    except ServerDownOrUnreachableError, excp:
        sys.stderr.write("ERROR: server not reachable or doesn't support " \
                                                                "RedFish.\n")
        sys.exit()
    except Exception, excp:
        raise excp

    ex2_get_base_registry(REDFISH_OBJ)
  