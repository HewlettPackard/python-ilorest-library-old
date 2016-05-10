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

def ex13_dump_ilo_nic(redfishobj):
    sys.stdout.write("\nEXAMPLE 13: Get iLO NIC state\n")
    instances = redfishobj.search_for_type("Manager.")

    for instance in instances:
        rsp = redfishobj.redfish_get(instance["@odata.id"])
        response = redfishobj.redfish_get(rsp.dict["EthernetInterfaces"]\
                                                                ["@odata.id"])

        for entry in response.dict["Members"]:
            nic = redfishobj.redfish_get(entry["@odata.id"])

            if nic.dict["Status"]["State"] == "Enabled":
                sys.stdout.write("\t" + nic.dict["Name"] + "\n")

                if "MACAddress" not in nic.dict:
                    sys.stderr.write("\tNo MACAddress information available (no"
                           " 'MACAddress' property in NIC resource)\n")
                else:
                    sys.stdout.write("\tMAC: " + str(nic.dict["MACAddress"]) + \
                                                                        "\n")

                sys.stdout.write("\tSpeed: " + str(nic.dict["SpeedMbps"]) + \
                                                                        "\n")
                if not "Autosence" in nic.dict:
                    sys.stderr.write("\tNo Autosence information available\n")
                else:
                    sys.stdout.write("\tAutosense:  " + \
                                            str(nic.dict["Autosense"]) + "\n")

                sys.stdout.write("\tFull Duplex:  " + \
                                            str(nic.dict["FullDuplex"]) + "\n")
                if "FQDN" not in nic.dict:
                    sys.stderr.write("\tNo FQDN information available\n")
                else:
                    sys.stdout.write("\tFQDN:  " + str(nic.dict["FQDN"]) + "\n")

                for addr in nic.dict["IPv4Addresses"]:
                    sys.stdout.write("\tIPv4 Address:  " + addr["Address"] 
                           + " from " + addr["AddressOrigin"] + "\n")
                if "IPv6Addresses" not in nic.dict:
                    sys.stderr.write("\tIPv6Addresses information not "\
                                                                "available\n")
                else:
                    for addr in nic.dict["IPv6Addresses"]:
                        sys.stdout.write("\tIPv6 Address:  " + addr["Address"] 
                               + " from " + addr["AddressOrigin"] + "\n")

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

    # Create a REDFISH object
    try:
        REDFISH_OBJ = RedfishObject(iLO_host, iLO_account, iLO_password)
    except ServerDownOrUnreachableError, excp:
        sys.stderr.write("ERROR: server not reachable or doesn't support " \
                                                                "RedFish.\n")
        sys.exit()
    except Exception, excp:
        raise excp

    ex13_dump_ilo_nic(REDFISH_OBJ)
  