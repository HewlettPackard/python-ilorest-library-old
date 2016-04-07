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


"""

Provides examples of using the HP RESTful API on iLO for common use cases.  This is for tutorial/example purposes only.

---------------------------------------------------------------------------------------------------------------------
IMPORTANT!!!
---------------------------------------------------------------------------------------------------------------------
When developing a client for the HP RESTful API, be sure to not code based upon assumptions that are not guaranteed.
Search for, and note any 'NOTE' comments in this code to read about ways to avoid incorrect assumptions.

The reason avoiding these assumptions is so important is that implementations may vary across systems and firmware
versions, and we want your code to work consistently.

---------------------------------------------------------------------------------------------------------------------
STARTING ASSUMPTIONS
---------------------------------------------------------------------------------------------------------------------

On URIs:

The HP RESTful API is a "hypermedia API" by design.  This is to avoid building in restrictive assumptions to the
data model that will make it difficult to adapt to future hardware implementations.  A hypermedia API avoids these
assumptions by making the data model discoverable via links between resources.

A URI should be treated by the client as opaque, and thus should not be attempted to be understood or deconstructed
by the client.  Only specific top level URIs (any URI in this sample code) may be assumed, and even these may be
absent based upon the implementation (e.g. there might be no /rest/v1/Systems collection on something that doesn't
have compute nodes.)

The other URIs must be discovered dynamically by following href links.  This is because the API will eventually be
implemented on a system that breaks any existing data model "shape" assumptions we may make now.  In particular,
clients should not make assumptions about the URIs for the resource members of a collection.  For instance, the URI of
a collection member will NOT always be /rest/v1/.../collection/1, or 2.  On Moonshot a System collection member might be
/rest/v1/Systems/C1N1.

This sounds very complicated, but in reality (as these examples demonstrate), if you are looking for specific items,
the traversal logic isn't too complicated.

On Resource Model Traversal:

Although the resources in the data model are linked together, because of cross link references between resources,
a client may not assume the resource model is a tree.  It is a graph instead, so any crawl of the data model should
keep track of visited resources to avoid an infinite traversal loop.

A reference to another resource is any property called "href" no matter where it occurs in a resource.

An external reference to a resource outside the data model is referred to by a property called "extref".  Any
resource referred to by extref should not be assumed to follow the conventions of the API.

On Resource Versions:

Each resource has a "Type" property with a value of the format Tyepname.x.y.z where
* x = major version - incrementing this is a breaking change to the schema
* y = minor version - incrementing this is a non-breaking additive change to the schema
* z = errata - non-breaking change

Because all resources are versioned and schema also have a version, it is possible to design rules for "nearest"
match (e.g. if you are interacting with multiple services using a common batch of schema files).  The mechanism
is not prescribed, but a client should be prepared to encounter both older and newer versions of resource types.

On HTTP POST to create:

WHen POSTing to create a resource (e.g. create an account or session) the guarantee is that a successful response
includes a "Location" HTTP header indicating the resource URI of the newly created resource.  The POST may also
include a representation of the newly created object in a JSON response body but may not.  Do not assume the response
body, but test it.  It may also be an ExtendedError object.

HTTP REDIRECT:

All clients must correctly handle HTTP redirect.  We (or Redfish) may eventually need to use redirection as a way
to alias portions of the data model.

FUTURE:  Asynchronous tasks

In the future some operations may start asynchonous tasks.  In this case, the client should recognized and handle
HTTP 202 if needed and the 'Location' header will point to a resource with task information and status.

JSON-SCHEMA:

The json-schema available at /rest/v1/Schemas governs the content of the resources, but keep in mind:
* not every property in the schema is implemented in every implementation.
* some properties are schemed to allow both null and anotehr type like string or integer.

Robust client code should check both the existence and type of interesting properties and fail gracefully if
expectations are not met.

GENERAL ADVICE:

Clients should always be prepared for:
* unimplemented properties (e.g. a property doesn't apply in a particular case)
* null values in some cases if the value of a property is not currently known due to system conditions
* HTTP status codes other than 200 OK.  Can your code handle an HTTP 500 Internal Server Error with no other info?
* URIs are case insensitive
* HTTP header names are case insensitive
* JSON Properties and Enum values are case sensitive
* A client should be tolerant of any set of HTTP headers the service returns

"""

import sys
import json
import logging
import urlparse
import jsonpatch

from ilorest import AuthMethod, ilorest_logger, redfish_client
from ilorest.rest.v1_helper import ServerDownOrUnreachableError


#Config logger used by HPE Restful library
LOGGERFILE = "RedfishApiExamples.log"
LOGGERFORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOGGER = ilorest_logger(LOGGERFILE, LOGGERFORMAT, logging.INFO)
LOGGER.info("HPE Redfish API examples")

def ex1_get_resource_directory(redfishobj):
    sys.stdout.write("\nEXAMPLE 1: Find and store the resource directory " + "\n")
    response = redfishobj.redfish_get("/redfish/v1/resourcedirectory/")
    resources = {}

    if response.status == 200:
        sys.stdout.write("\tFound resource directory at /redfish/v1/resource" \
                                                            "directory" + "\n")
        resources["resources"] = response.dict["Instances"]
        return resources
    else:
        sys.stderr.write("\tResource directory missing at /redfish/v1/resource"\
                                                            "directory" + "\n")

def ex2_get_base_registry(redfishobj):
    sys.stdout.write("\nEXAMPLE 2: Find and return registry " + "\n")
    response = redfishobj.redfish_get("/redfish/v1/Registries/")
    messages = {}
    
    for entry in response.dict["Members"]:
        if not [x for x in ["/Base/", "/iLO/"] if x in entry["@odata.id"]]:
            continue
        else:
            registry = redfishobj.redfish_get(entry["@odata.id"])
        
        for location in registry.dict["Location"]:  
            reg_resp = redfishobj.redfish_get(location["Uri"]["extref"])

            if reg_resp.status == 200:
                sys.stdout.write("\tFound " + reg_resp.dict["RegistryPrefix"] \
                                    + " at " + location["Uri"]["extref"] + "\n")
                messages[reg_resp.dict["RegistryPrefix"]] = \
                                                    reg_resp.dict["Messages"]
            else:
                sys.stdout.write("\t" + reg_resp.dict["RegistryPrefix"] + \
                         " not found at " + location["Uri"]["extref"] + "\n")

    return messages

def ex3_change_bios_setting(redfishobj, bios_property, property_value, \
                                                            bios_password=None):
    sys.stdout.write("\nEXAMPLE 3: Change a BIOS setting\n")
    instances = redfishobj.search_for_type("Bios.")

    for instance in instances:
        body = {bios_property: property_value}
        response = redfishobj.redfish_patch(instance["@odata.id"], body, \
                                            optionalpassword=bios_password)
        redfishobj.error_handler(response)

def ex4_reset_server(redfishobj, bios_password=None):
    sys.stdout.write("\nEXAMPLE 4: Reset a server\n")
    instances = redfishobj.search_for_type("ComputerSystem.")

    for instance in instances:
        body = dict()
        body["Action"] = "Reset"
        body["ResetType"] = "ForceRestart"

        response = redfishobj.redfish_post(instance["@odata.id"], body)
        redfishobj.error_handler(response)

def ex5_enable_secure_boot(redfishobj, secure_boot_enable, bios_password=None):
    sys.stdout.write("\nEXAMPLE 5: Enable/Disable UEFI Secure Boot\n")
    instances = redfishobj.search_for_type("SecureBoot.")

    for instance in instances:
        body = {"SecureBootEnable": secure_boot_enable}
        response = redfishobj.redfish_patch(instance["@odata.id"], body, \
                                            optionalpassword=bios_password)
        redfishobj.error_handler(response)

def ex6_bios_revert_default(redfishobj):
    sys.stdout.write("\nEXAMPLE 6: Revert BIOS settings to default\n")
    instances = redfishobj.search_for_type("Bios.")

    for instance in instances:
        body = {"BaseConfig": "default"}
        response = redfishobj.redfish_put(instance["@odata.id"], body)
        redfishobj.error_handler(response)

def ex7_change_boot_order(redfishobj, bios_password=None):
    sys.stdout.write("\nEXAMPLE 7: Change Boot Order (UEFI)\n")
    instances = redfishobj.search_for_type("ServerBootSettings.")

    for instance in instances:
        response = redfishobj.redfish_get(instance["@odata.id"])
        bootorder = response.dict["PersistentBootConfigOrder"]
    
        #TODO: Need to change the persistent boot order here
        body = dict()
        body["PersistentBootConfigOrder"] = bootorder

        response = redfishobj.redfish_patch(instance["@odata.id"], body, \
                                            optionalpassword=bios_password)            
        redfishobj.error_handler(response)

def ex8_change_temporary_boot_order(redfishobj, boottarget, bios_password=None):
    sys.stdout.write("\nEXAMPLE 8: Change temporary boot order (one time boot" \
                                                    " or temporary override)\n")
    instances = redfishobj.search_for_type("ComputerSystem.")

    for instance in instances:
        response = redfishobj.redfish_get(instance["@odata.id"])
        bootoptions = response.dict["Boot"]

        # TODO need to find a list of supported sources
#         if boottarget not in bootoptions["BootSourceOverrideSupported"]:
#             sys.stderr.write("ERROR: %s is not a supported boot option.\n" \
#                                                             % boottarget)

        body = dict()
        body["Boot"] = dict()
        body["Boot"]["BootSourceOverrideTarget"] = boottarget

        response = redfishobj.redfish_patch(instance["@odata.id"], body, \
                                            optionalpassword=bios_password)            
        redfishobj.error_handler(response)

def ex9_find_ilo_mac_address(redfishobj):
    sys.stdout.write("\nEXAMPLE 9: Find iLO's MAC Addresses\n")
    instances = redfishobj.search_for_type("Manager.")

    for instance in instances:
        tmp = redfishobj.redfish_get(instance["@odata.id"])  
        response = redfishobj.redfish_get(tmp.dict["EthernetInterfaces"]\
                                                                ["@odata.id"])

        for entry in response.dict["Members"]:
            ethernet = redfishobj.redfish_get(entry["@odata.id"])

            if "MACAddress" not in ethernet.dict:
                sys.stderr.write("\tNIC resource does not contain " \
                                                    "'MACAddress' property\n")
            else:
                sys.stdout.write("\t" + ethernet.dict["Name"] + " = " + \
                                     ethernet.dict["MACAddress"] + "\t(" + \
                                     ethernet.dict["Status"]["State"] + ")\n")

def ex10_add_ilo_user_account(redfishobj, new_ilo_loginname, new_ilo_username, \
                                 new_ilo_password, irc=None, cfg=None, \
                                 virtual_media=None, usercfg=None, vpr=None):
    sys.stdout.write("\nEXAMPLE 10: Create an iLO User Account\n")
    instances = redfishobj.search_for_type("AccountService.")

    for instance in instances:
        rsp = redfishobj.redfish_get(instance["@odata.id"])

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

        newrsp = redfishobj.redfish_post(rsp.dict["Accounts"]["@odata.id"], \
                                                                        body)
        redfishobj.error_handler(newrsp)

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
                    body["Oem"] = {"Hp": body_oemhp}

                newrsp = redfishobj.redfish_patch(entry["@odata.id"], body)
                redfishobj.error_handler(newrsp)
                return
            
    sys.stderr.write("Account not found\n")

def ex12_remove_ilo_account(redfishobj, ilo_loginname_to_remove):
    sys.stdout.write("\nEXAMPLE 12: Remove an iLO account\n")
    instances = redfishobj.search_for_type("AccountService.")

    for instance in instances:
        response = redfishobj.redfish_get(instance["@odata.id"])
        accounts = redfishobj.redfish_get(response.dict["Accounts"]["@odata.id"])

        for entry in accounts.dict["Members"]:
            account = redfishobj.redfish_get(entry["@odata.id"])

            if account.dict["UserName"] == ilo_loginname_to_remove:
                newrsp = redfishobj.redfish_delete(entry["@odata.id"])
                redfishobj.error_handler(newrsp)
                return
            
    sys.stderr.write("Account not found\n")

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

def ex14_sessions(redfishobj, login_account, login_password):
    sys.stdout.write("\nEXAMPLE 14: Create/Use/Delete a user session\n")
    new_session = {"UserName": login_account, "Password": login_password}
    response = redfishobj.redfish_post("/redfish/v1/Sessions", new_session)
    redfishobj.error_handler(response)
    
    if response.status == 201:
        session_uri = response.getheader("location")
        session_uri = urlparse.urlparse(session_uri)
        sys.stdout.write("\tSession " + session_uri.path + " created\n")

        x_auth_token = response.getheader("x-auth-token")
        sys.stdout.write("\tSession key " + x_auth_token + " created\n")

        # Delete the created session
        sessresp = redfishobj.redfish_delete(session_uri.path)
        redfishobj.error_handler(sessresp)
    else:
        sys.stderr.write("ERROR: failed to create a session.\n")

def ex15_set_uid_light(redfishobj, uid):
    sys.stdout.write("\nEXAMPLE 15: Set UID Light on or off\n")
    instances = redfishobj.search_for_type("ComputerSystem.")

    for instance in instances:
        body = dict()
        if uid:
            body["IndicatorLED"] = "Lit"
        else:
            body["IndicatorLED"] = "Off"

        response = redfishobj.redfish_patch(instance["@odata.id"], body)
        redfishobj.error_handler(response)

def ex16_computer_details(redfishobj):
    sys.stdout.write("\nEXAMPLE 16: Dump host computer details\n")
    instances = redfishobj.search_for_type("ComputerSystem.")

    for instance in instances:
        response = redfishobj.redfish_get(instance["@odata.id"])

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
                                            response.dict["BiosVersion"] + "\n")

        sys.stdout.write("\tMemory:  " + 
               str(response.dict["MemorySummary"]["TotalSystemMemoryGiB"]) + \
                                                                        " GB\n")

        sys.stdout.write("\tProcessors:  " + \
                     str(response.dict["ProcessorSummary"]["Count"]) + " x " + \
                     str(response.dict["ProcessorSummary"]["Model"])+ "\n")

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

def ex17_mount_virtual_media_iso(redfishobj, iso_url, boot_on_next_server_reset):
    sys.stdout.write("\nEXAMPLE 17: Mount iLO Virtual Media DVD ISO from URL\n")
    instances = redfishobj.search_for_type("Manager.")

    for instance in instances:
        rsp = redfishobj.redfish_get(instance["@odata.id"])
        rsp = redfishobj.redfish_get(rsp.dict["VirtualMedia"]["@odata.id"])

        for vmlink in rsp.dict["Members"]:
            response = redfishobj.redfish_get(vmlink["@odata.id"])

            if response.status == 200 and "DVD" in response.dict["MediaTypes"]:
                body = {"Image": iso_url}
                
                # TODO need to check for redfish support
                if (iso_url is not None and \
                                        boot_on_next_server_reset is not None):
                    body["Oem"] = {"Hp": {"BootOnNextServerReset": \
                                                    boot_on_next_server_reset}}
    
                    response = redfishobj.redfish_patch(vmlink["@odata.id"], body)
                    redfishobj.error_handler(response)
            elif response.status != 200:
                redfishobj.error_handler(response)

def ex18_set_server_asset_tag(redfishobj, asset_tag):
    sys.stdout.write("\nEXAMPLE 18: Set Computer Asset Tag\n")
    instances = redfishobj.search_for_type("ComputerSystem.")

    for instance in instances:
        body = {"AssetTag": asset_tag}
        response = redfishobj.redfish_patch(instance["@odata.id"], body)
        redfishobj.error_handler(response)

def ex19_reset_ilo(redfishobj):
    sys.stdout.write("\nEXAMPLE 19: Reset iLO\n")
    instances = redfishobj.search_for_type("Manager.")

    for instance in instances:
        body = {"Action": "Reset"}
        response = redfishobj.redfish_post(instance["@odata.id"], body)
        redfishobj.error_handler(response)

def ex20_get_ilo_nic(redfishobj, get_active):
    sys.stdout.write("\nEXAMPLE 20: Get iLO's NIC configuration\n")
    instances = redfishobj.search_for_type("Manager.")

    for instance in instances:
        tmp = redfishobj.redfish_get(instance["@odata.id"])  
        response = redfishobj.redfish_get(tmp.dict["EthernetInterfaces"]\
                                                                ["@odata.id"])

        for entry in response.dict["Members"]:
            nic = redfishobj.redfish_get(entry["@odata.id"])

            if get_active and nic.dict["Status"]["State"] == "Enabled":
                sys.stdout.write("Active\t" + entry["@odata.id"] + ": " + \
                                                    json.dumps(nic.dict) + "\n")
            elif get_active == False and nic.dict["Status"]["State"] == \
                                                                    "Disabled":
                sys.stdout.write("InActive\t" + entry["@odata.id"] + ": " + \
                                                    json.dumps(nic.dict) + "\n")

def ex21_set_active_ilo_nic(redfishobj, shared_nic):
    sys.stdout.write("\nEXAMPLE 21: Set the active iLO NIC\n")
    instances = redfishobj.search_for_type("Manager.")
    selected_nic_uri = None

    for instance in instances:
        tmp = redfishobj.redfish_get(instance["@odata.id"])  
        response = redfishobj.redfish_get(tmp.dict["EthernetInterfaces"]\
                                                                ["@odata.id"])
        
        for entry in response.dict["Members"]:
            nic = redfishobj.redfish_get(entry["@odata.id"])

            try:
                if (nic.dict["Oem"]["Hp"]["SupportsFlexibleLOM"] == True and \
                                                            shared_nic == True):
                    selected_nic_uri = nic.dict["links"]["self"]["href"]
                    break
            except KeyError:
                pass
    
            try:
                if (nic.dict["Oem"]["Hp"]["SupportsLOM"] == True and \
                                                            shared_nic == True):
                    selected_nic_uri = nic.dict["links"]["self"]["href"]
                    break
            except KeyError:
                pass
    
            if not shared_nic:
                selected_nic_uri = entry["@odata.id"]
                break
            elif not selected_nic_uri:
                sys.stderr.write("\tShared NIC is not supported\n")
                break
    
        if selected_nic_uri:
            body = {"Oem": {"Hp": {"NICEnabled": True}}}
            response = redfishobj.redfish_patch(selected_nic_uri, body)
            redfishobj.error_handler(response)

def ex22_dump_iml(redfishobj):
    sys.stdout.write("\nEXAMPLE 22: Dump Integrated Management Log\n")
    instances = redfishobj.search_for_type("LogService.")

    for instance in instances:
        if instance["@odata.id"].endswith("IML/"):
            tmp = redfishobj.redfish_get(instance["@odata.id"])
            rsp = redfishobj.redfish_get(tmp.dict["Entries"]["@odata.id"])

            for entry in rsp.dict["Members"]:
                response = redfishobj.redfish_get(entry["@odata.id"])
                sys.stdout.write(response.dict["Severity"] + ": Class " + \
                     str(response.dict["Oem"]["Hp"]["Class"]) + \
                     " / Code " + str(response.dict["Oem"]["Hp"]["Code"]) + \
                     ":\t" + response.dict["Message"] + "\n")

def ex23_dump_ilo_event_log(redfishobj):
    sys.stdout.write("\nEXAMPLE 23: Dump iLO Event Log\n")
    instances = redfishobj.search_for_type("LogService.")

    for instance in instances:
        if instance["@odata.id"].endswith("IEL/"):
            tmp = redfishobj.redfish_get(instance["@odata.id"])
            rsp = redfishobj.redfish_get(tmp.dict["Entries"]["@odata.id"])

            for entry in rsp.dict["Members"]:
                response = redfishobj.redfish_get(entry["@odata.id"])
                sys.stdout.write(response.dict["Message"] + "\n")

def ex24_clear_iml(redfishobj):
    sys.stdout.write("\nEXAMPLE 24: Clear Integrated Management Log\n")
    instances = redfishobj.search_for_type("LogService.")

    for instance in instances:
        if instance["@odata.id"].endswith("IML/"):
            body = {"Action": "ClearLog"}
            response = redfishobj.redfish_post(instance["@odata.id"], body)
            redfishobj.error_handler(response)

def ex25_clear_ilo_event_log(redfishobj):
    sys.stdout.write("\nEXAMPLE 25: Clear iLO Event Log\n")
    instances = redfishobj.search_for_type("LogService.")

    for instance in instances:
        if instance["@odata.id"].endswith("IEL/"):
            body = {"Action": "ClearLog"}
            response = redfishobj.redfish_post(instance["@odata.id"], body)
            redfishobj.error_handler(response)

def ex26_configure_snmp(redfishobj, snmp_mode, snmp_alerts):
    sys.stdout.write("\nEXAMPLE 26: Configure iLO SNMP Settings\n")
    instances = redfishobj.search_for_type("SnmpService.")

    for instance in instances:
        body = {"Mode": snmp_mode, "AlertsEnabled": snmp_alerts}
        response = redfishobj.redfish_patch(instance["@odata.id"], body)
        redfishobj.error_handler(response)

def ex27_get_schema(redfishobj, schema_prefix):
    sys.stdout.write("\nEXAMPLE 27:  Find and return schema " + \
                                                        schema_prefix + "\n")
    response = redfishobj.redfish_get("/redfish/v1/Schemas")

    for entry in response.dict["Members"]:
        schema = redfishobj.redfish_get(entry["@odata.id"])

        if schema.dict["Schema"].startswith(schema_prefix):
            for location in schema.dict["Location"]:
                extref_uri = location["Uri"]["extref"]
                response = redfishobj.redfish_get(extref_uri)
                if response.status == 200:
                    sys.stdout.write("\tFound " + schema_prefix + " at "\
                                                        + extref_uri + "\n")
                    return
                else:
                    sys.stderr.write("\t" + schema_prefix + " not found at " \
                                                        + extref_uri + "\n")
                    return

    sys.stderr.write("Registry " + schema_prefix + " not found.\n")

def ex28_set_ilo_timezone(redfishobj, olson_timezone):
    sys.stdout.write("\nEXAMPLE 28: Set iLO's Timezone\n")
    sys.stdout.write("\tNOTE: This only works if iLO is NOT configured to " \
                                    "take time settings from DHCP v4 or v6\n")
    instances = redfishobj.search_for_type("HpiLODateTime.")

    for instance in instances:
        response = redfishobj.redfish_get(instance["@odata.id"])

        for timezone in response.dict["TimeZoneList"]:
            if timezone["Name"].startswith(olson_timezone):
                body = {"TimeZone": {"Index": timezone["Index"]}}
                response = redfishobj.redfish_patch(instance["@odata.id"], body)
                redfishobj.error_handler(response)

def ex29_set_ilo_ntp_servers(redfishobj, ntp_servers):
    sys.stdout.write("\nEXAMPLE 29:  Set iLO's NTP Servers\n")
    instances = redfishobj.search_for_type("HpiLODateTime.")

    for instance in instances:
        response = redfishobj.redfish_get(instance["@odata.id"])

        sys.stdout.write("\tCurrent iLO Date/Time Settings:  " +
                json.dumps(response.dict["ConfigurationSettings"]) + "\n")
        sys.stdout.write("\tCurrent iLO NTP Servers:  " +
                            json.dumps(response.dict["NTPServers"]) + "\n")

        body = {"StaticNTPServers": ntp_servers}
        response = redfishobj.redfish_patch(instance["@odata.id"], body)
        redfishobj.error_handler(response)

def ex30_get_powermetrics_average(redfishobj):
    sys.stdout.write("\nEXAMPLE 30: Report PowerMetrics Average Watts\n")
    instances = redfishobj.search_for_type("Power.")

    for instance in instances:
        response = redfishobj.redfish_get(instance["@odata.id"])
        
        if "PowerControl" not in response.dict or "AverageConsumedWatts" not \
                        in response.dict["PowerControl"][0]["PowerMetrics"] or \
                        "IntervalInMin" not in response.dict["PowerControl"]\
                                                            [0]["PowerMetrics"]:
            sys.stdout.write("\tPowerMetrics resource does not contain " \
                         "'AverageConsumedWatts' or 'IntervalInMin' property\n")
        else:
            sys.stdout.write("\t" + " AverageConsumedWatts = " + \
                    str(response.dict["PowerControl"][0]["PowerMetrics"]\
                        ["AverageConsumedWatts"]) + " watts over a " + \
                     str(response.dict["PowerControl"][0]["PowerMetrics"]\
                         ["IntervalInMin"]) + " minute moving average\n")

def ex31_set_license_key(redfishobj, iLO_Key):
    sys.stdout.write("\nEXAMPLE 31: Set iLO License Key\n")
    instances = redfishobj.search_for_type("Manager.")

    for instance in instances:
        rsp = redfishobj.redfish_get(instance["@odata.id"])

        body = dict()
        body["LicenseKey"] = iLO_Key
        response = redfishobj.redfish_post(rsp.dict["Oem"]["Hp"]["Links"]\
                                       ["LicenseService"]["@odata.id"], body)
        redfishobj.error_handler(response)

class RedfishObject(object):
    def __init__(self, host, login_account, login_password):
        try:
            self.redfish_client = redfish_client(base_url=host, \
                      username=login_account, password=login_password, \
                      default_prefix="/redfish/v1")
        except:
            raise
        self.redfish_client.login(auth=AuthMethod.SESSION)
        self.SYSTEMS_RESOURCES = ex1_get_resource_directory(self)
        self.MESSAGE_REGISTRIES = ex2_get_base_registry(self)

    def __del__(self):
        try:
            self.redfish_client.logout()
        except AttributeError, excp:
            pass

    def search_for_type(self, type):
        instances = []

        for item in self.SYSTEMS_RESOURCES["resources"]:
            foundsettings = False

            if "@odata.type" in item and type.lower() in \
                                                    item["@odata.type"].lower():
                for entry in self.SYSTEMS_RESOURCES["resources"]:
                    if (item["@odata.id"] + "/settings/").lower() == \
                                                (entry["@odata.id"]).lower():
                        foundsettings = True

                if not foundsettings:
                    instances.append(item)

        if not instances:
            sys.stderr.write("\t'%s' resource or feature is not " \
                                            "supported on this system\n" % type)
        return instances

    def error_handler(self, response):
        if not self.MESSAGE_REGISTRIES:
            sys.stderr.write("ERROR: No message registries found.")

        try:
            message = json.loads(response.text)
            newmessage = message["error"]["@Message.ExtendedInfo"][0]\
                                                        ["MessageId"].split(".")
        except:
            sys.stdout.write("\tNo extended error information returned by " \
                                                                    "iLO.\n")
            return

        for err_mesg in self.MESSAGE_REGISTRIES:
            if err_mesg != newmessage[0]:
                continue
            else:
                for err_entry in self.MESSAGE_REGISTRIES[err_mesg]:
                    if err_entry == newmessage[3]:
                        sys.stdout.write("\tiLO return code %s: %s\n" % (\
                                 message["error"]["@Message.ExtendedInfo"][0]\
                                 ["MessageId"], self.MESSAGE_REGISTRIES\
                                 [err_mesg][err_entry]["Description"]))

    def redfish_get(self, suburi):
        """REDFISH GET"""
        return self.redfish_client.get(path=suburi)

    def redfish_patch(self, suburi, request_body, optionalpassword=None):
        """REDFISH PATCH"""
        sys.stdout.write("PATCH " + str(request_body) + " to " + suburi + "\n")
        response = self.redfish_client.patch(path=suburi, body=request_body, \
                                            optionalpassword=optionalpassword)
        sys.stdout.write("PATCH response = " + str(response.status) + "\n")

        return response

    def redfish_put(self, suburi, request_body, optionalpassword=None):
        """REDFISH PUT"""
        sys.stdout.write("PUT " + str(request_body) + " to " + suburi + "\n")
        response = self.redfish_client.put(path=suburi, body=request_body, \
                                            optionalpassword=optionalpassword)
        sys.stdout.write("PUT response = " + str(response.status) + "\n")

        return response


    def redfish_post(self, suburi, request_body):
        """REDFISH POST"""
        sys.stdout.write("POST " + str(request_body) + " to " + suburi + "\n")
        response = self.redfish_client.post(path=suburi, body=request_body)
        sys.stdout.write("POST response = " + str(response.status) + "\n")

        return response


    def redfish_delete(self, suburi):
        """REDFISH DELETE"""
        sys.stdout.write("DELETE " + suburi + "\n")
        response = self.redfish_client.delete(path=suburi)
        sys.stdout.write("DELETE response = " + str(response.status) + "\n")

        return response

if __name__ == "__main__":
    # When running on the server locally use the following commented values
    # iLO_host = "blobstore://."
    # iLO_account = "None"
    # iLO_password = "None"

    # When running remotely connect using the iLO address, iLO account name, 
    # and password to send https requests
    iLO_host = "https://10.0.0.100"
    login_account = "admin"
    login_password = "password"

    # Create a REDFISH object
    try:
        REDFISH_OBJ = RedfishObject(iLO_host, login_account, login_password)
    except ServerDownOrUnreachableError, excp:
        sys.stderr.write("ERROR: server not reachable or doesn't support " \
                                                                "RedFish.\n")
        sys.exit()
    except Exception, excp:
        raise excp

    # These examples are comment out because they are now part of the RedfishObject
    # class. They are initiated when you create a RedfishObject class object.
    #ex1_get_resource_directory(REDFISH_OBJ)
    #ex2_get_base_registry(REDFISH_OBJ)

    # Uncomment the examples you would like to execute
    #ex3_change_bios_setting(REDFISH_OBJ, "AdminName", "New Name")
    #ex4_reset_server(REDFISH_OBJ)
    #ex5_enable_secure_boot(REDFISH_OBJ, False)
    #ex6_bios_revert_default(REDFISH_OBJ)
    #ex7_change_boot_order(REDFISH_OBJ)
    #ex8_change_temporary_boot_order(REDFISH_OBJ, "Hdd")
    #ex9_find_ilo_mac_address(REDFISH_OBJ)
    #ex10_add_ilo_user_account(REDFISH_OBJ, "name", "username", "password")
    #ex11_modify_ilo_user_account(REDFISH_OBJ, "name", "newname", "newusername", "newpassword")
    #ex12_remove_ilo_account(REDFISH_OBJ, "newname")
    #ex13_dump_ilo_nic(REDFISH_OBJ)
    #ex14_sessions(REDFISH_OBJ, "admin", "admin123")
    #ex15_set_uid_light(REDFISH_OBJ, True)
    #ex16_computer_details(REDFISH_OBJ)
    #ex17_mount_virtual_media_iso(REDFISH_OBJ, "http://10.0.0.100/test.iso", True)
    #ex18_set_server_asset_tag(REDFISH_OBJ, "assettaghere")
    #ex19_reset_ilo(REDFISH_OBJ)
    #ex20_get_ilo_nic(REDFISH_OBJ, True)
    #ex21_set_active_ilo_nic(REDFISH_OBJ, False)
    #ex22_dump_iml(REDFISH_OBJ)
    #ex23_dump_ilo_event_log(REDFISH_OBJ)
    #ex24_clear_iml(REDFISH_OBJ)
    #ex25_clear_ilo_event_log(REDFISH_OBJ)
    #ex26_configure_snmp(REDFISH_OBJ, "Agentless", False)
    #ex27_get_schema(REDFISH_OBJ, "ComputerSystem")
    #ex28_set_ilo_timezone(REDFISH_OBJ, "America/Chicago")
    #ex29_set_ilo_ntp_servers(REDFISH_OBJ, ["192.168.0.1", "192.168.0.2"])
    #ex30_get_powermetrics_average(REDFISH_OBJ)
    #ex31_set_license_key(REDFISH_OBJ, "test_iLO_Key")

