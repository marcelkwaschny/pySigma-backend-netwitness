"""Module to test the netwitness fortinet processing pipeline"""

import pytest
from sigma.collection import SigmaCollection

from sigma.backends.netwitness import NetWitnessBackend
from sigma.pipelines.netwitness.fortinet import netwitness_fortinet_pipeline


@pytest.fixture(name="netwitness_backend_fortinet_pipeline")
def netwitness_backend_fortinet_pipeline_fixture() -> NetWitnessBackend:
    """Fixture for the netwitness backend instance with a fortinet processing pipeline

    Returns:
        NetWitnessBackend: NetWitness backend instance
    """

    return NetWitnessBackend(processing_pipeline=netwitness_fortinet_pipeline())


def test_fortinet_adding_fortinet_device_type_transformation(netwitness_backend_fortinet_pipeline: NetWitnessBackend):
    """Test"""

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


def test_fortinet_adding_fortimail_device_type_transformation(netwitness_backend_fortinet_pipeline: NetWitnessBackend):
    """Test"""

    conversion_result: str = netwitness_backend_fortinet_pipeline.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                product: fortimail
            detection:
                selection:
                    direction: 'out'
                    classifier: 'Virus Signature'
                condition: selection
            """
        )
    )

    assert conversion_result == [
        "device.type = 'fortinetfortimail' && (direction = 'out' && classifier = 'Virus Signature')"
    ]
