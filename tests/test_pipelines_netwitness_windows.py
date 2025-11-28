"""Module to test the NetWitness windows processing pipeline"""

import pytest
from sigma.collection import SigmaCollection

from sigma.backends.netwitness import NetWitnessBackend
from sigma.pipelines.netwitness.windows import netwitness_windows_pipeline


@pytest.fixture(name="netwitness_backend_windows_pipeline")
def netwitness_backend_windows_pipeline_fixture() -> NetWitnessBackend:
    """Fixture for the NetWitness backend instance with a windows processing pipeline

    Returns:
        NetWitnessBackend: NetWitness backend instance
    """

    return NetWitnessBackend(processing_pipeline=netwitness_windows_pipeline())  # type: ignore[arg-type]


def test_windows_event_id_transformation_to_string(netwitness_backend_windows_pipeline: NetWitnessBackend) -> None:
    """Test transformation of event ids to string because this is a text field in NetWitness"""

    conversion_result: str = netwitness_backend_windows_pipeline.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                product: windows
            detection:
                sel:
                    EventID: 4688
                    CommandLine: test
                condition: sel
            """
        )
    )

    assert conversion_result == ["device.type = 'windows' && (reference.id = '4688' && param = 'test')"]


def test_windows_process_creation(netwitness_backend_windows_pipeline: NetWitnessBackend) -> None:
    """Test basic field mapping and injection of the process creation condition"""

    conversion_result: str = netwitness_backend_windows_pipeline.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    CommandLine: test
                condition: sel
            """
        )
    )

    assert conversion_result == ["device.type = 'windows' && (reference.id = '4688' && param = 'test')"]


def test_netwitness_param_contains_backslash(netwitness_backend_windows_pipeline: NetWitnessBackend) -> None:
    """Test basic field mapping and injection of the process creation condition"""

    conversion_result: str = netwitness_backend_windows_pipeline.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    CommandLine|contains: C:\\Windows
                condition: sel
            """
        )
    )

    assert conversion_result == ["device.type = 'windows' && (reference.id = '4688' && param contains 'C:\\Windows')"]


def test_windows_with_windash_modifier(netwitness_backend_windows_pipeline: NetWitnessBackend) -> None:
    """Test basic field mapping and injection of the process creation condition"""

    conversion_result: str = netwitness_backend_windows_pipeline.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    CommandLine|windash|contains:
                    - '-f'
                condition: sel
            """
        )
    )

    assert conversion_result == [
        "device.type = 'windows' && (reference.id = '4688' && (param contains '-f','/f','–f','—f','―f'))"
    ]


def test_windows_with_contains_modifier_with_ending_escape_char(
    netwitness_backend_windows_pipeline: NetWitnessBackend,
) -> None:
    """Test if rule which has a field that ends with the escape char is converted correctly"""

    conversion_result: str = netwitness_backend_windows_pipeline.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                product: windows
                service: security
            detection:
                sel:
                    NewProcessName|contains:
                    - C:\\Windows\\Temp\\
                condition: sel
            """
        )
    )

    assert conversion_result == ["device.type = 'windows' && process contains 'C:\\Windows\\Temp\\'"]


def test_field_in_filter_with_null_value(netwitness_backend_windows_pipeline: NetWitnessBackend) -> None:
    """Test if the rule is converted correctly if a null value check in a filter is used"""

    conversion_result: str = netwitness_backend_windows_pipeline.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    Field: Test
                filter:
                    CommandLine: null
                condition: selection and not filter
            """
        )
    )

    assert conversion_result == [
        "device.type = 'windows' && (reference.id = '4688' && (Field = 'Test' && (NOT (param !exists || param = '-'))))"
    ]
