import sys
import json
import logging
from ilorest import AuthMethod, rest_client, ilorest_logger


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

#Config logger used by HPE Restful library
LOGGERFILE = "RestfulApiExamples.log"
LOGGERFORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOGGER = ilorest_logger(LOGGERFILE, LOGGERFORMAT, logging.INFO)
LOGGER.info("HPE Restful API examples")



class RestObject(object):
    def __init__(self, host, login_account, login_password):
        self.rest_client = rest_client(base_url=host, \
                          username=login_account, password=login_password, \
                          default_prefix="/rest/v1")
        self.rest_client.login(auth=AuthMethod.SESSION)
        self.SYSTEMS_RESOURCES = self.ex1_get_resource_directory()
        self.MESSAGE_REGISTRIES = self.ex2_get_base_registry()

    def __del__(self):
        self.rest_client.logout()

    def search_for_type(self, type):
        instances = []

        for item in self.SYSTEMS_RESOURCES["resources"]:
            foundsettings = False

            if type.lower() in item["Type"].lower():
                for entry in self.SYSTEMS_RESOURCES["resources"]:
                    if (item["href"] + "/settings").lower() == \
                                                        (entry["href"]).lower():
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
            newmessage = message["Messages"][0]["MessageID"].split(".")
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
                                   message["Messages"][0]["MessageID"], \
                                   self.MESSAGE_REGISTRIES[err_mesg][err_entry]\
                                   ["Description"]))

    def rest_get(self, suburi):
        """REST GET"""
        return self.rest_client.get(path=suburi)

    def rest_patch(self, suburi, request_body, optionalpassword=None):
        """REST PATCH"""
        sys.stdout.write("PATCH " + str(request_body) + " to " + suburi + "\n")
        response = self.rest_client.patch(path=suburi, body=request_body, \
                                            optionalpassword=optionalpassword)
        sys.stdout.write("PATCH response = " + str(response.status) + "\n")

        return response

    def rest_put(self, suburi, request_body, optionalpassword=None):
        """REST PUT"""
        sys.stdout.write("PUT " + str(request_body) + " to " + suburi + "\n")
        response = self.rest_client.put(path=suburi, body=request_body, \
                                            optionalpassword=optionalpassword)
        sys.stdout.write("PUT response = " + str(response.status) + "\n")

        return response


    def rest_post(self, suburi, request_body):
        """REST POST"""
        sys.stdout.write("POST " + str(request_body) + " to " + suburi + "\n")
        response = self.rest_client.post(path=suburi, body=request_body)
        sys.stdout.write("POST response = " + str(response.status) + "\n")

        return response


    def rest_delete(self, suburi):
        """REST DELETE"""
        sys.stdout.write("DELETE " + suburi + "\n")
        response = self.rest_client.delete(path=suburi)
        sys.stdout.write("DELETE response = " + str(response.status) + "\n")

        return response
    
    def ex1_get_resource_directory(self):
        response = self.rest_get("/rest/v1/resourcedirectory")
        resources = {}
    
        if response.status == 200:
            resources["resources"] = response.dict["Instances"]
            return resources
        else:
            sys.stderr.write("\tResource directory missing at /rest/v1/resource" \
                                                                "directory" + "\n")
    
    def ex2_get_base_registry(self):
        response = self.rest_get("/rest/v1/Registries")
        messages = {}
        
        identifier = None
        
        for entry in response.dict["Items"]:
            if "Id" in entry:
                identifier = entry["Id"]
            else:
                identifier = entry["Schema"].split(".")[0]
    
            if identifier not in ["Base", "iLO"]:
                continue
    
            for location in entry["Location"]:  
                reg_resp = self.rest_get(location["Uri"]["extref"])
    
                if reg_resp.status == 200:
                    messages[identifier] = reg_resp.dict["Messages"]
                else:
                    sys.stdout.write("\t" + identifier + " not found at "\
                                                + location["Uri"]["extref"] + "\n")
    
        return messages
