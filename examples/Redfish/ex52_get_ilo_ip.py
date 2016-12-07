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
from _redfishobject import RedfishObject
from redfish.rest.v1_helper import ServerDownOrUnreachableError

def ex52_get_ilo_ip(redfishobj):
    sys.stdout.write("\nEXAMPLE 52: Get iLO IP locally\n")
    instances = redfishobj.search_for_type("Manager.")

    for instance in instances:
        response = redfishobj.redfish_get(instance["@odata.id"])
        ethernet_rsp =  redfishobj.redfish_get(response.dict\
                                    ["EthernetInterfaces"]["@odata.id"])
        
        for item in ethernet_rsp.dict["Members"]:
            item_rsp = redfishobj.redfish_get(item["@odata.id"])
            if not item_rsp.dict["IPv4Addresses"][0]["Address"] == "0.0.0.0":
                sys.stdout.write("\t" + item_rsp.dict["IPv4Addresses"][0]\
                                 ["Address"] + "\n")
        redfishobj.error_handler(response)
        
if __name__ == "__main__":
    # When running on the server locally use the following commented values
    # While this example can be run remotely, it is used locally to locate the
    # iLO IP address
    iLO_https_url = "blobstore://."
    iLO_account = "None"
    iLO_password = "None"

    # When running remotely connect using the iLO secured (https://) address, 
    # iLO account name, and password to send https requests
    # iLO_https_url acceptable examples:
    # "https://10.0.0.100"
    # "https://f250asha.americas.hpqcorp.net"
    # iLO_https_url = "https://10.0.0.100"
    # iLO_account = "admin"
    # iLO_password = "password"

    # Create a REDFISH object
    try:
        REDFISH_OBJ = RedfishObject(iLO_https_url, iLO_account, iLO_password)
    except ServerDownOrUnreachableError, excp:
        sys.stderr.write("ERROR: server not reachable or doesn't support " \
                                                                "RedFish.\n")
        sys.exit()
    except Exception, excp:
        raise excp
    ex52_get_ilo_ip(REDFISH_OBJ)

