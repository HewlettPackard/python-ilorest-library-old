""" Redfish restful library """

__all__ = ['rest', 'ris', 'hpilo']
__version__ = "1.0.0"

import logging
from redfish.rest.v1 import AuthMethod
from redfish.rest.v1 import redfish_client, rest_client

def redfish_logger(file_name, log_format, log_level=logging.ERROR):
    formatter = logging.Formatter(log_format)
    fh = logging.FileHandler(file_name)
    fh.setFormatter(formatter)
    logger = logging.getLogger(__name__)
    logger.addHandler(fh)
    logger.setLevel(log_level)
    return logger
