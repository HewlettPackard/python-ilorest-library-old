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

def ex53_update_ilo_firmware(restobj, fw_url=None, tpm_flag=None):
    sys.stdout.write("\nEXAMPLE 53: Update iLO Firmware\n")
    instances = restobj.search_for_type("Manager.")

    for instance in instances:
        response = restobj.rest_get(instance["href"])
        body = dict()
        body["Action"] = "InstallFromURI"
        body["FirmwareURI"] = {"FirmwareURI": fw_url}
        body["TPMOverrideFlag"] = {"TPMOverrideFlag": tpm_flag}
        response = restobj.rest_post(response.dict["Oem"]\
                                         ["Hp"]["links"]["UpdateService"]\
                                         ["href"], body)
        restobj.error_handler(response)
        
if __name__ == "__main__":
    # When running on the server locally use the following commented values
    # While this example can be run remotely, it is used locally to locate the
    # iLO IP address
    #iLO_https_url = "blobstore://."
    #iLO_account = "None"
    #iLO_password = "None"

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
    ex53_update_ilo_firmware(REST_OBJ, "http://test.com/ilo4_244.bin", False)

