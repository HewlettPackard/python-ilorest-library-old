from setuptools import setup, find_packages


setup(name='python-ilorest-library',
      version='1.0.0',
      description='Hewlett Packard Enterprise Python library',
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
