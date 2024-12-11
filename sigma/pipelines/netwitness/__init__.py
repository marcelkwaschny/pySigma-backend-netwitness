"""Mappings of identifier to pipelines used by pySigma"""

from .windows import netwitness_windows_pipeline  # pylint:disable=import-error

pipelines = {
    "netwitness_windows": netwitness_windows_pipeline,
}
