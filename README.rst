python-ilorestful-library
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
 
 
 .. _windows: http://h20564.www2.hpe.com/hpsc/swd/public/detail?swItemId=MTX_43efdf5067924c78a34bf384c9&swEnvOid=4168
 .. _linux: http://h20564.www2.hpe.com/hpsc/swd/public/detail?swItemId=MTX-5f86c051cbd042a6975250da39&swEnvOid=4168

Usage
----------

.. code-block:: python
	import ilorest

Create a Rest Object
~~~~~~~~~~~~~~~~~~~~~~~~~
 In RestfulApiExamples.py module, a rest object instance is created by calling the **rest_client** method with four parameters: IP address, iLO user name, iLO password and the default prefix.
 
.. code-block:: python

	REST_OBJ = ilorest.rest_client(base_url=host,username=login_account, \
                              password=login_password, default_prefix='/rest/v1') 

Create a Redfish Object
~~~~~~~~~~~~~~~~~~~~~~~~~
 Just like Rest object, a Redfish object instance in RedfishAPiExamples.py is created by calling the **redfish_client** method with four parameters: IP address, iLO user name, iLO password and the default prefix.

.. code-block:: python

	REST_OBJ = ilorest.redfish_client(base_url=host,username=login_account, \ 
                                 password=login_password, default_prefix='/redfish/v1')   	

Login to the server
~~~~~~~~~~~~~~~~~~~~~~~~~
 You must login to the server to create a session. You can continue with a basic authentication, but it would less secure.

.. code-block:: python

	REST_OBJ.login(auth="session")

Perform a GET operation
~~~~~~~~~~~~~~~~~~~~~~~~~
 Do a GET operation on a given path.

.. code-block:: python

	response = REST_OBJ.get("/rest/v1/systems/1", None)

Logout the created session
~~~~~~~~~~~~~~~~~~~~~~~~~
 Make sure you logout every session you create as it will remain alive until it times out.

.. code-block:: python

	REST_OBJ.logout()
	
Contributing
----------

 1. Fork it!
 2. Create your feature branch: `git checkout -b my-new-feature`
 3. Commit your changes: `git commit -am 'Add some feature'`
 4. Push to the branch: `git push origin my-new-feature`
 5. Submit a pull request :D

History
----------

  04/01/2016: Initial Commit
  06/23/2016: Release of v1.1.0
  07/25/2016: Release of v1.2.0

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
