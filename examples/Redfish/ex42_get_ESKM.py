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
import json
from redfishobject import RedfishObject
from ilorest.rest.v1_helper import ServerDownOrUnreachableError

def ex42_get_ESKM(redfishobj):
    sys.stdout.write("\nEXAMPLE 42: Get ESKM configuration\n")
    instances = redfishobj.search_for_type("SecurityService.")

    for instance in instances:
        tmp = redfishobj.redfish_get(instance["@odata.id"])
        response = redfishobj.redfish_get(tmp.dict["Links"]["ESKM"]["@odata.id"])

        sys.stdout.write("\tPrimaryKeyServerAddress:  " +
                         json.dumps(response.dict["PrimaryKeyServerAddress"])\
                         + "\n")
        sys.stdout.write("\tPrimaryKeyServerPort:  " +
                         json.dumps(response.dict["PrimaryKeyServerPort"])\
                         + "\n")
        sys.stdout.write("\tSecondaryKeyServerAddress:  " +
                         json.dumps(response.dict["SecondaryKeyServerAddress"])\
                          + "\n")
        sys.stdout.write("\tSecondaryKeyServerPort:  " +
                         json.dumps(response.dict["SecondaryKeyServerPort"])\
                          + "\n")
        sys.stdout.write("\tKeyServerRedundancyReq:  " +
                         json.dumps(response.dict["KeyServerRedundancyReq"])\
                          + "\n")

        sys.stdout.write("\tAccountGroup:  " +
                         json.dumps(response.dict["KeyManagerConfig"]\
                                    ["AccountGroup"]) + "\n")
        sys.stdout.write("\tESKMLocalCACertificateName:  " +
                         json.dumps(response.dict["KeyManagerConfig"]\
                                    ["ESKMLocalCACertificateName"]) + "\n")
        sys.stdout.write("\tImportedCertificateIssuer:  " +
                         json.dumps(response.dict["KeyManagerConfig"]\
                                    ["ImportedCertificateIssuer"]) + "\n")

        sys.stdout.write("\tESKMEvents:  " +
                         json.dumps(response.dict["ESKMEvents"]) + "\n")

        tmp = response.dict["ESKMEvents"]
        for entry in tmp:
            sys.stdout.write("\tTimestamp : " + entry["Timestamp"] +\
                              "Event:  " +
                             json.dumps(entry["Event"]) + "\n")

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

    ex42_get_ESKM(REDFISH_OBJ)




