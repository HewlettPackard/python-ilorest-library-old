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
from restobject import RestObject

def ex43_get_EncryptionSettings(restobj):

    sys.stdout.write("\nEXAMPLE 43: Dump EncryptionSettings\n")
    instances = restobj.search_for_type("HpSmartStorageArrayController.")

    types = ["Name","Model","SerialNumber","EncryptionBootPasswordSet",\
             "EncryptionCryptoOfficerPasswordSet",\
             "EncryptionLocalKeyCacheEnabled","EncryptionMixedVolumesEnabled",\
             "EncryptionPhysicalDriveCount","EncryptionRecoveryParamsSet",\
             "EncryptionStandaloneModeEnabled","EncryptionUserPasswordSet"]

    for instance in instances:
        response = restobj.rest_get(instance["href"])

        for item in types:
            sys.stdout.write("\tID:  " +
                             str(response.dict["@odata.id"]) + "\n")
            if item in response.dict:
                sys.stdout.write("\t" + item +
                                 str(response.dict[item]) + "\n")
            else:
                sys.stderr.write("\t" + item + "is not " \
                        "available on HpSmartStorageArrayController resource\n")

if __name__ == "__main__":
 
    iLO_host = "https://10.0.0.100"
    iLO_account =  "admin"
    iLO_password =  "password"
    
    # Create a REST object
    REST_OBJ = RestObject(iLO_host, iLO_account, iLO_password)
    ex43_get_EncryptionSettings(REST_OBJ)



