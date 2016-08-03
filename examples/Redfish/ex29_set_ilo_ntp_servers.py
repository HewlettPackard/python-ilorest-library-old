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
from _redfishobject import RedfishObject
from ilorest.rest.v1_helper import ServerDownOrUnreachableError

def ex29_set_ilo_ntp_servers(redfishobj, ntp_servers):
    sys.stdout.write("\nEXAMPLE 29:  Set iLO's NTP Servers\n")
    instances = redfishobj.search_for_type("HpiLODateTime.")

    for instance in instances:
        response = redfishobj.redfish_get(instance["@odata.id"])

        sys.stdout.write("\tCurrent iLO Date/Time Settings:  " +
                json.dumps(response.dict["ConfigurationSettings"]) + "\n")
        sys.stdout.write("\tCurrent iLO NTP Servers:  " +
                            json.dumps(response.dict["NTPServers"]) + "\n")

        body = {"StaticNTPServers": ntp_servers}
        response = redfishobj.redfish_patch(instance["@odata.id"], body)
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

    ex29_set_ilo_ntp_servers(REDFISH_OBJ, ["192.168.0.1", "192.168.0.2"])
  