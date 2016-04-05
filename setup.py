from setuptools import setup, find_packages


setup(name='python-ilorest-library',
      version='1.0.0',
      description='iLO Rest Python Library',
	  author = 'Hewlett Packard Enterprise',
	  author_email = 'jackgarcia77@gmail.com',
      classifiers=[
          'Development Status :: 3 - Alpha',
          'License :: OSI Approved :: Apache Software License',
          'Programming Language :: Python :: 2.7',
          'Topic :: Communications'
      ],
      keywords='HP Enterprise',
      url='https://github.com/HewlettPackard/python-ilorest-library',
      packages=find_packages('src'),
      package_dir={'': 'src'},
      install_requires=[
          'jsonpatch',
          'jsonpath_rw',
          'jsonpointer',
          'validictory',
          'urlparse2'
      ])
