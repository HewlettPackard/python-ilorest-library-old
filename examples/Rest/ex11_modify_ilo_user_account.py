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

def ex11_modify_ilo_user_account(restobj, ilo_login_name_to_modify, \
                new_ilo_loginname, new_ilo_username, new_ilo_password, \
                irc=None, cfg=None, virtual_media=None, usercfg=None, vpr=None):
    sys.stdout.write("\nEXAMPLE 11: Modify an iLO user account\n")
    instances = restobj.search_for_type("AccountService.")

    for instance in instances:
        response = restobj.rest_get(instance["href"])
        accounts = restobj.rest_get(response.dict["links"]["Accounts"]["href"])

        for account in accounts.dict["Items"]:
            if account["UserName"] == ilo_login_name_to_modify:
                body = {}
                body_oemhp = {}
                body_oemhp_privs = {}
    
                # if new loginname or password specified
                if new_ilo_password:
                    body["Password"] = new_ilo_password
                if new_ilo_loginname:
                    body["UserName"] = new_ilo_loginname
    
                # if different username specified
                if new_ilo_username:
                    body_oemhp["LoginName"] = new_ilo_username
    
                # if different privileges were requested (None = no change)
                if irc != None:
                    body_oemhp_privs["RemoteConsolePriv"] = irc
                if virtual_media != None:
                    body_oemhp_privs["VirtualMediaPriv"] = virtual_media
                if cfg != None:
                    body_oemhp_privs["iLOConfigPriv"] = cfg
                if usercfg != None:
                    body_oemhp_privs["UserConfigPriv"] = usercfg
                if vpr != None:
                    body_oemhp_privs["VirtualPowerAndResetPriv"] = vpr
    
                # component assembly
                if len(body_oemhp_privs):
                    body_oemhp["Privileges"] = body_oemhp_privs
                if len(body_oemhp):
                    body["Oem"] = {"Hp": body_oemhp}

                newrsp = restobj.rest_patch(account["links"]["self"]["href"], \
                                                                        body)
                restobj.error_handler(newrsp)
                return
            
    sys.stderr.write("Account not found\n")

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
    ex11_modify_ilo_user_account(REST_OBJ, "name", "newname", "newusername", "newpassword")
