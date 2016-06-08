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
from restobject import RestObject

def ex8_change_temporary_boot_order(restobj, boottarget, bios_password=None):
    sys.stdout.write("\nEXAMPLE 8: Change temporary boot order (one time boot" \
                                                    " or temporary override)\n")
    instances = restobj.search_for_type("ComputerSystem.")

    for instance in instances:
        response = restobj.rest_get(instance["href"])
        bootoptions = response.dict["Boot"]
        
        if boottarget not in bootoptions["BootSourceOverrideSupported"]:
            sys.stderr.write("ERROR: %s is not a supported boot option.\n" \
                                                            % boottarget)

        body = dict()
        body["Boot"] = dict()
        body["Boot"]["BootSourceOverrideTarget"] = boottarget

        response = restobj.rest_patch(instance["href"], body, \
                                            optionalpassword=bios_password)            
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
    ex8_change_temporary_boot_order(REST_OBJ, "Hdd")
 
