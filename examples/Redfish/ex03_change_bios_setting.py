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
from redfish.rest.v1 import ServerDownOrUnreachableError

def ex3_change_bios_setting(redfishobj, bios_property, property_value, \
                                                            bios_password=None):
    sys.stdout.write("\nEXAMPLE 3: Change a BIOS setting\n")
    instances = redfishobj.search_for_type("Bios.")
    if not len(instances) and redfishobj.typepath.defs.isgen9:
        sys.stderr.write("\nNOTE: This example requires the Redfish schema "\
                 "version TBD in the managed iLO. It will fail against iLOs"\
                 " with the 2.50 firmware or earlier. \n")

    for instance in instances:
        body = {bios_property: property_value}
        response = redfishobj.redfish_patch(instance["@odata.id"], body, \
                                            optionalpassword=bios_password)
        redfishobj.error_handler(response)

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

    # Create a REDFISH object
    try:
        REDFISH_OBJ = RedfishObject(iLO_https_url, iLO_account, iLO_password)
    except ServerDownOrUnreachableError, excp:
        sys.stderr.write("ERROR: server not reachable or doesn't support " \
                                                                "RedFish.\n")
        sys.exit()
    except Exception, excp:
        raise excp

    ex3_change_bios_setting(REDFISH_OBJ, "AdminName", "New Name")
  