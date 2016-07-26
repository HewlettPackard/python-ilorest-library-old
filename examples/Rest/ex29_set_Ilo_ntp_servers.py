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
from _restobject import RestObject

def ex29_set_ilo_ntp_servers(restobj, ntp_servers):
    sys.stdout.write("\nEXAMPLE 29:  Set iLO's NTP Servers\n")
    instances = restobj.search_for_type("HpiLODateTime.")

    for instance in instances:
        response = restobj.rest_get(instance["href"])

        sys.stdout.write("\tCurrent iLO Date/Time Settings:  " +
                json.dumps(response.dict["ConfigurationSettings"]) + "\n")
        sys.stdout.write("\tCurrent iLO NTP Servers:  " +
                            json.dumps(response.dict["NTPServers"]) + "\n")

        body = {"StaticNTPServers": ntp_servers}
        response = restobj.rest_patch(instance["href"], body)
        restobj.error_handler(response)
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
    
    #Create a REST object
    REST_OBJ = RestObject(iLO_host, iLO_account, iLO_password)
    ex29_set_ilo_ntp_servers(REST_OBJ, ["192.168.0.1", "192.168.0.2"])
