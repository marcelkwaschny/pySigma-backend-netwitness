"""Mappings of identifier to pipelines used by pySigma"""

from .netwitness import netwitness_windows_pipeline

pipelines = {
    "netwitness_windows": netwitness_windows_pipeline,
}
