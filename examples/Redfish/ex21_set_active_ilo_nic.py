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
from redfishobject import RedfishObject
from ilorest.rest.v1_helper import ServerDownOrUnreachableError

def ex21_set_active_ilo_nic(redfishobj, shared_nic):
    sys.stdout.write("\nEXAMPLE 21: Set the active iLO NIC\n")
    instances = redfishobj.search_for_type("Manager.")
    selected_nic_uri = None

    for instance in instances:
        tmp = redfishobj.redfish_get(instance["@odata.id"])  
        response = redfishobj.redfish_get(tmp.dict["EthernetInterfaces"]\
                                                                ["@odata.id"])
        
        for entry in response.dict["Members"]:
            nic = redfishobj.redfish_get(entry["@odata.id"])

            try:
                if (nic.dict["Oem"]["Hp"]["SupportsFlexibleLOM"] == True and \
                                                            shared_nic == True):
                    selected_nic_uri = nic.dict["links"]["self"]["href"]
                    break
            except KeyError:
                pass
    
            try:
                if (nic.dict["Oem"]["Hp"]["SupportsLOM"] == True and \
                                                            shared_nic == True):
                    selected_nic_uri = nic.dict["links"]["self"]["href"]
                    break
            except KeyError:
                pass
    
            if not shared_nic:
                selected_nic_uri = entry["@odata.id"]
                break
            elif not selected_nic_uri:
                sys.stderr.write("\tShared NIC is not supported\n")
                break
    
        if selected_nic_uri:
            body = {"Oem": {"Hp": {"NICEnabled": True}}}
            response = redfishobj.redfish_patch(selected_nic_uri, body)
            redfishobj.error_handler(response)

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

    ex21_set_active_ilo_nic(REDFISH_OBJ, False)
  