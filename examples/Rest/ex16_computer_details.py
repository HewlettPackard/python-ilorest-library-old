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
from _restobject import RestObject

def ex16_computer_details(restobj):
    sys.stdout.write("\nEXAMPLE 16: Dump host computer details\n")
    instances = restobj.search_for_type("ComputerSystem.")

    for instance in instances:
        response = restobj.rest_get(instance["href"])

        sys.stdout.write("\tManufacturer:  " + \
                                str(response.dict["Manufacturer"]) + "\n")
        sys.stdout.write("\tModel:  " + str(response.dict["Model"]) + "\n")
        sys.stdout.write("\tSerial Number:  " + \
                                str(response.dict["SerialNumber"]) + "\n")
        if "VirtualSerialNumber" in response.dict:
            sys.stdout.write("\tVirtual Serial Number:  " +
                   str(response.dict["VirtualSerialNumber"]) + "\n")
        else:
            sys.stderr.write("\tVirtual Serial Number information not " \
                                        "available on system resource\n")
        sys.stdout.write("\tUUID:  " + str(response.dict["UUID"]) + "\n")

        if "VirtualUUID" in response.dict["Oem"]["Hp"]:
            sys.stdout.write("\tVirtualUUID:  " + \
                     str(response.dict["Oem"]["Hp"]["VirtualUUID"]) + "\n")
        else:
            sys.stderr.write("\tVirtualUUID not available system " \
                                                            "resource\n")
        if "AssetTag" in response.dict:
            sys.stdout.write("\tAsset Tag:  " + response.dict["AssetTag"] \
                                                                    + "\n")
        else:
            sys.stderr.write("\tNo Asset Tag information on system " \
                                                            "resource\n")
        sys.stdout.write("\tBIOS Version: " + \
                 response.dict["Bios"]["Current"]["VersionString"] + "\n")

        sys.stdout.write("\tMemory:  " + 
               str(response.dict["Memory"]["TotalSystemMemoryGB"]) +" GB\n")

        sys.stdout.write("\tProcessors:  " + \
                 str(response.dict["Processors"]["Count"]) + " x " + \
                 str(response.dict["Processors"]["ProcessorFamily"])+ "\n")

        if "Status" not in response.dict or "Health" not in \
                                                    response.dict["Status"]:
            sys.stdout.write("\tStatus/Health information not available in "
                                                        "system resource\n")
        else:
            sys.stdout.write("\tHealth:  " + \
                             str(response.dict["Status"]["Health"]) + "\n")

        if "HostCorrelation" in response.dict:
            if "HostFQDN" in response.dict["HostCorrelation"]:
                sys.stdout.write("\tHost FQDN:  " + \
                     response.dict["HostCorrelation"]["HostFQDN"] + "\n")
                
            if "HostMACAddress" in response.dict["HostCorrelation"]:
                for mac in response.dict["HostCorrelation"]["HostMACAddress"]:
                    sys.stdout.write("\tHost MAC Address:  " + str(mac) + "\n")

            if "HostName" in response.dict["HostCorrelation"]:
                sys.stdout.write("\tHost Name:  " + \
                     response.dict["HostCorrelation"]["HostName"] + "\n")

            if "IPAddress" in response.dict["HostCorrelation"]:
                for ip_address in response.dict["HostCorrelation"]\
                                                            ["IPAddress"]:
                    if ip_address:
                        sys.stdout.write("\tHost IP Address:  " + \
                                                    str(ip_address) + "\n")


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
    
    #Create a REST object
    REST_OBJ = RestObject(iLO_https_host, iLO_account, iLO_password)
    ex16_computer_details(REST_OBJ)
    
