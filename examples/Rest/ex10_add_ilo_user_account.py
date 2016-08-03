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

def ex10_add_ilo_user_account(restobj, new_ilo_loginname, new_ilo_username, \
                                 new_ilo_password, irc=None, cfg=None, \
                                 virtual_media=None, usercfg=None, vpr=None):
    sys.stdout.write("\nEXAMPLE 10: Create an iLO User Account\n")
    instances = restobj.search_for_type("AccountService.")

    for instance in instances:
        rsp = restobj.rest_get(instance["href"])

        body = {"UserName": new_ilo_loginname, "Password": \
                                                new_ilo_password, "Oem": {}}
        body["Oem"]["Hp"] = {}
        body["Oem"]["Hp"]["LoginName"] = new_ilo_username
        body["Oem"]["Hp"]["Privileges"] = {}
        body["Oem"]["Hp"]["Privileges"]["RemoteConsolePriv"] = irc
        body["Oem"]["Hp"]["Privileges"]["iLOConfigPriv"] = cfg
        body["Oem"]["Hp"]["Privileges"]["VirtualMediaPriv"] = virtual_media
        body["Oem"]["Hp"]["Privileges"]["UserConfigPriv"] = usercfg
        body["Oem"]["Hp"]["Privileges"]["VirtualPowerAndResetPriv"] = vpr

        newrsp = restobj.rest_post(rsp.dict["links"]["Accounts"]["href"], body)
        restobj.error_handler(newrsp)

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
    ex10_add_ilo_user_account(REST_OBJ, "name", "username", "password")
