"""Common configurations for all tests"""

import pytest

from sigma.backends.netwitness import NetWitnessBackend
from sigma.pipelines.netwitness.netwitness import netwitness_windows_pipeline


@pytest.fixture(name="netwitness_backend")
def netwitness_backend_fixture() -> NetWitnessBackend:
    """Fixture for the netwitness backend instance

    Returns:
        NetWitnessBackend: NetWitness backend instance
    """

    return NetWitnessBackend()


@pytest.fixture(name="netwitness_backend_windows_pipeline")
def netwitness_backend_windows_pipeline_fixture() -> NetWitnessBackend:
    """Fixture for the netwitness backend instance with a windows processing pipeline

    Returns:
        NetWitnessBackend: NetWitness backend instance
    """

    return NetWitnessBackend(processing_pipeline=netwitness_windows_pipeline())
