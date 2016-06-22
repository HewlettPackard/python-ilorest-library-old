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

def ex46_get_ahs_data(restobj):
    sys.stdout.write("\nEXAMPLE 46: Get AHS Data\n")
    instances = restobj.search_for_type("Manager.")

    for instance in instances:
        tmp = restobj.rest_get(instance["href"])
        response = restobj.rest_get(tmp.dict["Oem"]["Hp"]["links"]\
                                    ["ActiveHealthSystem"]["href"])

        sys.stdout.write("Fetching AHS Data, this may take minutes to hours\n")
        ahslink = restobj.rest_get(response.dict["links"]["AHSLocation"]\
                                   ["extref"])

        with open("data.ahs", 'wb') as ahsoutput:
            ahsoutput.write(ahslink.read)
            ahsoutput.close()

        sys.stdout.write("AHS Data saved successfully as data.ahs\n")

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
    ex46_get_ahs_data(REST_OBJ)

