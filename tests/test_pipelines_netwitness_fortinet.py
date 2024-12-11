"""Module to test the NetWitness Fortinet processing pipeline"""

import pytest
from sigma.collection import SigmaCollection

from sigma.backends.netwitness import NetWitnessBackend
from sigma.pipelines.netwitness.fortinet import netwitness_fortinet_pipeline


@pytest.fixture(name="netwitness_backend_fortinet_pipeline")
def netwitness_backend_fortinet_pipeline_fixture() -> NetWitnessBackend:
    """Fixture for the NetWitness backend instance with a Fortinet processing pipeline

    Returns:
        NetWitnessBackend: NetWitness backend instance
    """

    return NetWitnessBackend(processing_pipeline=netwitness_fortinet_pipeline())


def test_fortinet_adding_fortinet_device_type_transformation(netwitness_backend_fortinet_pipeline: NetWitnessBackend):
    """Test if the logsource product 'fortinet' will be transformed to the correct device type"""

    conversion_result: str = netwitness_backend_fortinet_pipeline.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                product: fortinet
            detection:
                selection:
                    severity:
                        - 'high'
                        - 'critical'
                condition: selection
            """
        )
    )

    assert conversion_result == ["device.type = 'fortinet' && (severity = 'high','critical')"]


def test_fortinet_category_mapping_and_integer_conversion(netwitness_backend_fortinet_pipeline: NetWitnessBackend):
    """Test if the logsource product 'fortimail' will be transformed to the correct device type"""

    conversion_result: str = netwitness_backend_fortinet_pipeline.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                product: fortinet
                service: ips
            detection:
                selection:
                    dstip: '127.0.0.1'
                    dstport: '1337'
                condition: selection
            """
        )
    )

    assert conversion_result == [
        "category = 'ips' && (device.type = 'fortinet' && (ip.dst = 127.0.0.1 && ip.dstport = 1337))"
    ]
