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
from _redfishobject import RedfishObject
from redfish.rest.v1 import ServerDownOrUnreachableError

def ex11_modify_ilo_user_account(redfishobj, ilo_login_name_to_modify, \
                new_ilo_loginname, new_ilo_username, new_ilo_password, \
                irc=None, cfg=None, virtual_media=None, usercfg=None, vpr=None):
    sys.stdout.write("\nEXAMPLE 11: Modify an iLO user account\n")
    instances = redfishobj.search_for_type("AccountService.")

    for instance in instances:
        rsp = redfishobj.redfish_get(instance["@odata.id"])
        accounts = redfishobj.redfish_get(rsp.dict["Accounts"]["@odata.id"])

        for entry in accounts.dict["Members"]:
            account = redfishobj.redfish_get(entry["@odata.id"])

            if account.dict["UserName"] == ilo_login_name_to_modify:
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
                    if redfishobj.typepath.defs.isgen9:
                        body["Oem"] = {"Hp": body_oemhp}
                    else:
                        body["Oem"] = {"Hpe": body_oemhp}

                newrsp = redfishobj.redfish_patch(entry["@odata.id"], body)
                redfishobj.error_handler(newrsp)
                return
            
    sys.stderr.write("Account not found\n")

if __name__ == "__main__":
    # When running on the server locally use the following commented values
    # iLO_https_url = "blobstore://."
    # iLO_account = "None"
    # iLO_password = "None"

    # When running remotely connect using the iLO secured (https://) address, 
    # iLO account name, and password to send https requests
    # iLO_https_url acceptable examples:
    # "https://10.0.0.100"
    # "https://f250asha.americas.hpqcorp.net"
    iLO_https_url = "https://10.0.0.100"
    iLO_account = "admin"
    iLO_password = "password"

    # Create a REDFISH object
    try:
        REDFISH_OBJ = RedfishObject(iLO_https_url, iLO_account, iLO_password)
    except ServerDownOrUnreachableError, excp:
        sys.stderr.write("ERROR: server not reachable or doesn't support " \
                                                                "RedFish.\n")
        sys.exit()
    except Exception, excp:
        raise excp

    ex11_modify_ilo_user_account(REDFISH_OBJ, "name", "newname", \
                                                "newusername", "newpassword")
  