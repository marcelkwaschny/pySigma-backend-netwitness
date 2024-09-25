"""Tests for the netwitness backend"""

import pytest
from sigma.collection import SigmaCollection

from sigma.backends.netwitness import NetWitnessBackend


@pytest.fixture(name="netwitness_backend")
def netwitness_backend_fixture() -> NetWitnessBackend:
    """Fixture for the netwitness backend instance

    Returns:
        NetWitnessBackend: NetWitness backend instance
    """

    return NetWitnessBackend()


def test_netwitness_and_expression(netwitness_backend: NetWitnessBackend):
    """Basic test for an and expression"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
            """
        )
    )

    assert conversion_result == ["fieldA = 'valueA' && fieldB = 'valueB'"]


def test_netwitness_or_expression(netwitness_backend: NetWitnessBackend):
    """Basic test for an or expression"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
            """
        )
    )

    assert conversion_result == ["fieldA = 'valueA' || fieldB = 'valueB'"]


def test_netwitness_and_or_expression(netwitness_backend: NetWitnessBackend):
    """Test if list of values gets converted to a list expression"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
            """
        )
    )

    assert conversion_result == ["(fieldA = 'valueA1','valueA2') && (fieldB = 'valueB1','valueB2')"]


def test_netwitness_or_and_expression(netwitness_backend: NetWitnessBackend):
    """Basic test for selection groups divided by an or expression"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
            """
        )
    )
    expected = ["(fieldA = 'valueA1' && fieldB = 'valueB1') || (fieldA = 'valueA2' && fieldB = 'valueB2')"]

    assert conversion_result == expected


def test_netwitness_in_expression(netwitness_backend: NetWitnessBackend):
    """Test in expression with wildcard in value"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
            """
        )
    )

    assert conversion_result == ["fieldA = 'valueA','valueB' || fieldA begins 'valueC'"]


def test_netwitness_regex_modifier(netwitness_backend: NetWitnessBackend):
    """Test conversion with basic regex for a value"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
            """
        )
    )

    assert conversion_result == ["fieldA regex 'foo.*bar' && fieldB = 'foo'"]


def test_netwitness_cidr_modifier(netwitness_backend: NetWitnessBackend):
    """Test basic query with cidr modifier"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
            """
        )
    )

    assert conversion_result == ["field = 192.168.0.0/16"]


def test_netwitness_contains_modifier(netwitness_backend: NetWitnessBackend):
    """Test basic query with contains modifier"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains: foo
                condition: sel
            """
        )
    )

    assert conversion_result == ["fieldA contains 'foo'"]


def test_netwitness_contains_modifier_with_list(netwitness_backend: NetWitnessBackend):
    """Test basic query with contains modifier but with a list of values"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains:
                        # This is a comment
                        - foo
                        # This is a comment
                        - bar
                        - baz
                condition: sel
            """
        )
    )

    assert conversion_result == ["fieldA contains 'foo','bar','baz'"]


def test_netwitness_contains_all_modifier(netwitness_backend: NetWitnessBackend):
    """Test basic query with contains and all modifier"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains|all:
                        - foo
                        - bar
                condition: sel
            """
        )
    )

    assert conversion_result == ["fieldA contains 'foo' && fieldA contains 'bar'"]


def test_netwitness_base64_modifier(netwitness_backend: NetWitnessBackend):
    """Test basic query with base64 modifier"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    fieldA|base64: foo
                condition: selection
            """
        )
    )

    assert conversion_result == ["fieldA = 'Zm9v'"]


def test_netwitness_base64_offset_modifier(netwitness_backend: NetWitnessBackend):
    """Test basic query with base64offset modifier"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    fieldA|base64offset: foo
                condition: selection
            """
        )
    )

    assert conversion_result == ["fieldA = 'Zm9v','Zvb','mb2'"]


def test_netwitness_base64_offset_modifier_with_contains_modifier(netwitness_backend: NetWitnessBackend):
    """Test basic query with base64offset modifier"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    fieldA|base64offset|contains:
                        - foo
                        - bar
                condition: selection
            """
        )
    )

    assert conversion_result == ["fieldA contains 'Zm9v','Zvb','mb2','YmFy','Jhc','iYX'"]


def test_netwitness_startswith_modifier(netwitness_backend: NetWitnessBackend):
    """Test basic query with startswith modifier"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    fieldA|startswith: foo
                condition: selection
            """
        )
    )

    assert conversion_result == ["fieldA begins 'foo'"]


def test_netwitness_endswith_modifier(netwitness_backend: NetWitnessBackend):
    """Test basic query with endswith modifier"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    fieldA|endswith: foo
                condition: selection
            """
        )
    )

    assert conversion_result == ["fieldA ends 'foo'"]


def test_netwitness_greater_than_modifier(netwitness_backend: NetWitnessBackend):
    """Test basic query with greater than modifier"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    fieldA|gt: 10
                condition: selection
            """
        )
    )

    assert conversion_result == ["fieldA > 10"]


def test_netwitness_greater_equal_modifier(netwitness_backend: NetWitnessBackend):
    """Test basic query with greater equal modifier"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    fieldA|gte: 10
                condition: selection
            """
        )
    )

    assert conversion_result == ["fieldA >= 10"]


def test_netwitness_less_than_modifier(netwitness_backend: NetWitnessBackend):
    """Test basic query with less than modifier"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    fieldA|lt: 10
                condition: selection
            """
        )
    )

    assert conversion_result == ["fieldA < 10"]


def test_netwitness_less_equal_modifier(netwitness_backend: NetWitnessBackend):
    """Test basic query with less equal modifier"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    fieldA|lte: 10
                condition: selection
            """
        )
    )

    assert conversion_result == ["fieldA <= 10"]


def test_netwitness_windash_modifier(netwitness_backend: NetWitnessBackend):
    """Test basic query with windash modifier"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    fieldname|windash|contains: -f
                condition: selection
            """
        )
    )

    assert conversion_result == ["fieldname contains '-f','/f','–f','—f','―f'"]


def test_netwitness_windash_modifier_with_list(netwitness_backend: NetWitnessBackend):
    """Test conversion of query with list values and windash modifier"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    fieldname|windash|contains:
                        - " -param-name "
                        - " -f "
                condition: selection
            """
        )
    )

    assert conversion_result == [
        "fieldname contains ' -param-name ',' /param-name ',' –param-name ',' —param-name ',' ―param-name ',"
        "' -f ',' /f ',' –f ',' —f ',' ―f '"
    ]


def test_netwitness_not_condition(netwitness_backend: NetWitnessBackend):
    """Test basic not condition"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    fieldA:
                        - "foo"
                        - "bar"
                filter:
                    fieldB: filter
                condition: selection and not filter
            """
        )
    )

    assert conversion_result == ["(fieldA = 'foo','bar') && (NOT (fieldB = 'filter'))"]


def test_netwitness_not_condition_with_list_of_values(netwitness_backend: NetWitnessBackend):
    """Test basic not condition with a list of values"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    fieldA:
                        - "foo"
                        - "bar"
                filter:
                    fieldB:
                        - filter1
                        - filter2
                condition: selection and not filter
            """
        )
    )

    assert conversion_result == ["(fieldA = 'foo','bar') && (NOT (fieldB = 'filter1','filter2'))"]


def test_netwitness_with_multiple_filters(netwitness_backend: NetWitnessBackend):
    """Test conversion with multiple filters defined"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    FieldA|endswith: 'valueA'
                filter_1:
                    FieldB: null
                filter_2:
                    FieldB: ''
                condition: selection and not 1 of filter*
            """
        )
    )

    assert conversion_result == ["FieldA ends 'valueA' && (NOT (FieldB !exists || FieldB = '-' || FieldB = ''))"]


def test_netwitness_exists_modifier(netwitness_backend: NetWitnessBackend):
    """Test conversion with the exists modifier set to true"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    FieldA|exists: true
                condition: selection
            """
        )
    )

    assert conversion_result == ["FieldA exists"]


def test_netwitness_not_exists_modifier(netwitness_backend: NetWitnessBackend):
    """Test conversion with the exists modifier set to false"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(  # type: ignore
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    FieldA|exists: false
                condition: selection
            """
        )
    )

    assert conversion_result == ["FieldA !exists"]


def test_equal_char_in_list_contains(netwitness_backend: NetWitnessBackend):
    """Test conversion with the exists modifier set to false"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    FieldA|contains:
                        - field1=value1
                        - field2=value2
                condition: selection
            """
        )
    )

    assert conversion_result == ["FieldA contains 'field1=value1','field2=value2'"]
