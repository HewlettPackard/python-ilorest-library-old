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

def ex8_change_temporary_boot_order(redfishobj, boottarget, bios_password=None):
    sys.stdout.write("\nEXAMPLE 8: Change temporary boot order (one time boot" \
                                                    " or temporary override)\n")
    instances = redfishobj.search_for_type("ComputerSystem.")

    for instance in instances:
        response = redfishobj.redfish_get(instance["@odata.id"])
        bootoptions = response.dict["Boot"]

        # TODO need to find a list of supported sources
#         if boottarget not in bootoptions["BootSourceOverrideSupported"]:
#             sys.stderr.write("ERROR: %s is not a supported boot option.\n" \
#                                                             % boottarget)

        body = dict()
        body["Boot"] = dict()
        body["Boot"]["BootSourceOverrideTarget"] = boottarget

        response = redfishobj.redfish_patch(instance["@odata.id"], body, \
                                            optionalpassword=bios_password)            
        redfishobj.error_handler(response)

if __name__ == "__main__":
    # When running on the server locally use the following commented values
    # iLO_https_host = "blobstore://."
    # iLO_account = "None"
    # iLO_password = "None"

    # When running remotely connect using the iLO address, iLO account name, 
    # and password to send https requests
    iLO_https_host = "https://10.0.0.100"
    iLO_account = "admin"
    iLO_password = "password"

    # Create a REDFISH object
    try:
        REDFISH_OBJ = RedfishObject(iLO_https_host, iLO_account, iLO_password)
    except ServerDownOrUnreachableError, excp:
        sys.stderr.write("ERROR: server not reachable or doesn't support " \
                                                                "RedFish.\n")
        sys.exit()
    except Exception, excp:
        raise excp

    ex8_change_temporary_boot_order(REDFISH_OBJ, "Hdd")
  