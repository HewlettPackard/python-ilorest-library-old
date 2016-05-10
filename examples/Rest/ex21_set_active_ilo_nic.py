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

def ex21_set_active_ilo_nic(restobj, shared_nic):
    sys.stdout.write("\nEXAMPLE 21: Set the active iLO NIC\n")
    instances = restobj.search_for_type("Manager.")
    selected_nic_uri = None

    for instance in instances:
        tmp = restobj.rest_get(instance["href"])  
        response = restobj.rest_get(tmp.dict["links"]["EthernetNICs"]["href"])
        
        for nic in response.dict["Items"]:
            try:
                if (nic["Oem"]["Hp"]["SupportsFlexibleLOM"] == True and \
                                                            shared_nic == True):
                    selected_nic_uri = nic["links"]["self"]["href"]
                    break
            except KeyError:
                pass
    
            try:
                if (nic["Oem"]["Hp"]["SupportsLOM"] == True and \
                                                            shared_nic == True):
                    selected_nic_uri = nic["links"]["self"]["href"]
                    break
            except KeyError:
                pass
    
            if not shared_nic:
                selected_nic_uri = nic["links"]["self"]["href"]
                break
            elif not selected_nic_uri:
                sys.stderr.write("\tShared NIC is not supported\n")
                break
    
        if selected_nic_uri:
            body = {"Oem": {"Hp": {"NICEnabled": True}}}
            response = restobj.rest_patch(selected_nic_uri, body)
            restobj.error_handler(response)

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
    ex21_set_active_ilo_nic(REST_OBJ, False)
    
