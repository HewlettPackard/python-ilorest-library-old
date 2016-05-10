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

def ex26_configure_snmp(restobj, snmp_mode, snmp_alerts):
    sys.stdout.write("\nEXAMPLE 26: Configure iLO SNMP Settings\n")
    instances = restobj.search_for_type("SnmpService.")

    for instance in instances:
        body = {"Mode": snmp_mode, "AlertsEnabled": snmp_alerts}
        response = restobj.rest_patch(instance["href"], body)
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
    ex26_configure_snmp(REST_OBJ, "Agentless", False)
