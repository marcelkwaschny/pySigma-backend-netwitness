"""Mappings of identifier to pipelines used by pySigma"""

from .fortinet import netwitness_fortinet_pipeline  # pylint:disable=import-error
from .windows import netwitness_windows_pipeline  # pylint:disable=import-error

pipelines = {
    "netwitness_windows": netwitness_windows_pipeline,
    "netwitness_fortinet": netwitness_fortinet_pipeline,
}
