python-ilorest-library-old
==============
.. image:: https://travis-ci.org/HewlettPackard/python-ilorest-library.svg?branch=master
    :target: https://travis-ci.org/HewlettPackard/python-ilorest-library
.. image:: https://img.shields.io/pypi/v/python-ilorest-library.svg?maxAge=2592000
	:target: https://pypi.python.org/pypi/python-ilorest-library
.. image:: https://img.shields.io/github/release/HewlettPackard/python-ilorest-library.svg?maxAge=2592000
	:target: 
.. image:: https://img.shields.io/badge/license-Apache%202-blue.svg
	:target: https://raw.githubusercontent.com/HewlettPackard/python-ilorest-library/master/LICENSE
.. image:: https://img.shields.io/pypi/pyversions/python-ilorest-library.svg?maxAge=2592000
	:target: https://pypi.python.org/pypi/python-ilorest-library
.. image:: https://api.codacy.com/project/badge/Grade/1283adc3972d42b4a3ddb9b96660bc07
	:target: https://www.codacy.com/app/rexysmydog/python-ilorest-library?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=HewlettPackard/python-ilorest-library&amp;utm_campaign=Badge_Grade

Python iLOrest Library Announcement
----------

**The Python iLOrest Library team would like to inform you that this repository has reached its end of life. We will be continuing our efforts on the forked project directly from the DMTF repository. Click here_ to be redirected to the new project repository. **
 .. _here: https://github.com/HewlettPackard/python-redfish-library

.. contents:: :depth: 1

Description
----------

 HPE RESTful API for iLO is a RESTful application programming interface for the management of iLO and iLO Chassis Manager based HPE servers. REST (Representational State Transfer) is a web based software architectural style consisting of a set of constraints that focuses on a system's resources. iLO REST library performs the basic HTTP operations GET, POST, PUT, PATCH and DELETE on resources using the HATEOAS (Hypermedia as the Engine of Application State) REST architecture. The API allows the clients to manage and interact with iLO through a fixed URL and several URIs. Go to the `wiki <../../wiki>`_ for more details.

Installing
----------

.. code-block:: console

	pip install python-ilorest-library

Building from zip file source
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

	python setup.py sdist --formats=zip (this will produce a .zip file)
	cd dist
	pip install python-ilorest-library-x.x.x.zip

Requirements
----------

Remote communication
~~~~~~~~~~~~~~~~~~~~~~~~~

 No special requirements.
 
Inband communication
~~~~~~~~~~~~~~~~~~~~~~~~~

 To enable support for inband communications, you must download the DLL/SO for your system from: windows_ / linux_. It must be placed in your working environment path.
 
 
 .. _windows: https://downloads.hpe.com/pub/softlib2/software1/pubsw-windows/p1463761240/v124097/ilorest_chif.dll
 .. _linux: https://downloads.hpe.com/pub/softlib2/software1/pubsw-linux/p1093353304/v124098/ilorest_chif.so

Usage
----------
 A large set of examples is provided under the examples directory of this project. In addition to the directives present in this paragraph, you will find valuable implementation tips and tricks in those examples.

Import the relevant python module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 Depending on your desire to develop an HPE legacy REST or Redfish compliant application import the relevant python module.
 
 For a legacy REST application:
 
.. code-block:: python

	from _restobject import RestObject

 For Redfish compliant application:

.. code-block:: python

	from _redfishobject import RedfishObject

Create a REST or Redfish Object
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 Both legacy REST and Redfish Objects contain 3 parameters: the target secured URL (i.e. "https://ilo-IP" or "https://X.Y.Z.T"), an iLO user name and its password.
 To create a REST object, call the RestObject method:
.. code-block:: python

	REST_OBJ = RestObject(iLO_https_url, iLO_account, iLO_password)

 To crete a Redfish Object, call the RedfishObject method:
.. code-block:: python

	REDFISH_OBJ = RedfishObject(iLO_https_url, iLO_account, iLO_password)

Login to the server
~~~~~~~~~~~~~~~~~~~~~~~~~
 The login operation is performed when creating the REST_OBJ or REDFISH_OBJ. You can continue with a basic authentication, but it would less secure.

.. code-block:: python

	REST_OBJ.login(auth="session")

Perform a GET operation
~~~~~~~~~~~~~~~~~~~~~~~~~
 A simple GET operation can be performed to obtain the data present in any valid path.
 An example of rawget operation on the path "/rest/v1/system/1" is shown below:

.. code-block:: python

	response = REST_OBJ.get("/rest/v1/systems/1", None)

 A safer implementation of GET operation is performed in the library. This method finds the path of requested data based on the selected type. This will allow for the script to work seamlessly with any changes of location of data. The response obtained is also validated against schema for correct return values.

Logout the created session
~~~~~~~~~~~~~~~~~~~~~~~~~
 Make sure you logout every session you create as it will remain alive until it times out.

.. code-block:: python

	REST_OBJ.logout()

 A logout deletes the current sesssion from the system. The redfish_client and the rest_client object destructor includes a logout statement. 

Contributing
----------

 1. Fork it!
 2. Create your feature branch: `git checkout -b my-new-feature`
 3. Commit your changes: `git commit -am 'Add some feature'`
 4. Push to the branch: `git push origin my-new-feature`
 5. Submit a pull request :D

History
----------

  * 04/01/2016: Initial Commit
  * 06/23/2016: Release of v1.1.0
  * 07/25/2016: Release of v1.2.0
  * 08/02/2016: Release of v1.3.0
  * 09/06/2016: Release of v1.4.0
  * 11/04/2016: Release of v1.5.0
  * 12/06/2016: Release of v1.6.0
  * 01/17/2017: Release of v1.7.0
  * 02/01/2017: Release of v1.8.0
  * 03/22/2017: Release of v1.9.0
  * 04/12/2017: Release of v1.9.1

Copyright and License
---------------------

::

 Copyright 2016 Hewlett Packard Enterprise Development LP

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
