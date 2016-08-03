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
from ilorest.rest.v1_helper import ServerDownOrUnreachableError

def ex45_get_license_key(redfishobj):
    sys.stdout.write("\nEXAMPLE 45: Get iLO License Key\n")
    instances = redfishobj.search_for_type("HpiLOLicense.")
    license_result = dict()
    licenseproperties = ["License", "LicenseKey", "LicenseType"]
    
    for instance in instances:
        response = redfishobj.redfish_get(instance["@odata.id"])
        license_result["License"] = response.dict["License"]
        
        for licenseproperty in licenseproperties:
            sys.stdout.write("\t" + licenseproperty + ": " + \
                            str(response.dict[licenseproperty]) + "\n")
        redfishobj.error_handler(response)
        
    return (license_result)

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

    ex45_get_license_key(REDFISH_OBJ)



