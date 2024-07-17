"""Module to test NetWitness processing pipelines"""

from sigma.collection import SigmaCollection

from sigma.backends.netwitness import NetWitnessBackend


def test_windows_event_id_transformation_to_string(netwitness_backend_windows_pipeline: NetWitnessBackend):
    """Test transformation of event ids to string because this is a text field in netwitness"""

    conversion_result: str = netwitness_backend_windows_pipeline.convert(
        SigmaCollection.from_yaml( # type: ignore
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

    assert conversion_result == ["reference.id = '4688' && param = 'test'"]


def test_windows_process_creation(netwitness_backend_windows_pipeline: NetWitnessBackend):
    """Test basic field mapping and injection of the process creation condition"""

    conversion_result: str = netwitness_backend_windows_pipeline.convert(
        SigmaCollection.from_yaml( # type: ignore
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

    assert conversion_result == ["reference.id = '4688' && param = 'test'"]


def test_netwitness_param_contains_backslash(netwitness_backend_windows_pipeline: NetWitnessBackend):
    """Test basic field mapping and injection of the process creation condition"""

    conversion_result: str = netwitness_backend_windows_pipeline.convert(
        SigmaCollection.from_yaml( # type: ignore
            """
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    CommandLine|contains: C:\Windows
                condition: sel
            """
        )
    )

    assert conversion_result == ["reference.id = '4688' && param contains 'C:\Windows'"]
