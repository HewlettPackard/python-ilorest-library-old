import sys
import ilorest

# When running on the server locally use the following commented values
# iLO_host = "blobstore://."
# iLO_account = "None"
# iLO_password = "None"

# When running remotely connect using the iLO address, iLO account name, 
# and password to send https requests
iLO_host = "https://10.0.0.100"
login_account = "admin"
login_password = "password"

# Create a REST object
REST_OBJ = ilorest.rest_client(base_url=iLO_host,username=login_account, \
                      password=login_password, default_prefix='/rest/v1')

## Create a REDFISH object
#REST_OBJ = ilorest.redfish_client(base_url=iLO_host,username=login_account, \
#                          password=login_password, default_prefix='/redfish/v1')

# Login into the server and create a session
REST_OBJ.login(auth="session")

# Do a GET on a given path
response = REST_OBJ.get("/rest/v1/systems/1", None)

# Print out the response
sys.stdout.write("%s\n" % response)

# Logout of the current session
REST_OBJ.logout()