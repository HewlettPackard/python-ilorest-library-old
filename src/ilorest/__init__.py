"""HPE python modules

This package contains the following modules:

cpq_package -- classes for working with HPE SmartComponents

"""

__all__ = ['rest', 'ris', 'hpilo']
__version__ = "1.2.0"


from ilorest.rest.v1 import rest_client
from ilorest.rest.v1 import redfish_client
from ilorest.rest.v1_helper import AuthMethod
import logging


def ilorest_logger(file_name, log_format, log_level=logging.ERROR):
    formatter = logging.Formatter(log_format)
    fh = logging.FileHandler(file_name)
    fh.setFormatter(formatter)
    logger = logging.getLogger(__name__)
    logger.addHandler(fh)
    logger.setLevel(log_level)
    return logger
