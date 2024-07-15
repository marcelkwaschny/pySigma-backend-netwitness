"""Tests for the netwitness backend"""

import pytest
from sigma.backends.netwitness import NetWitnessBackend
from sigma.collection import SigmaCollection


@pytest.fixture(name="netwitness_backend")
def netwitness_backend_fixture() -> NetWitnessBackend:
    """Fixture for the netwitness backend instance

    Yields:
        Generator[NetWitnessBackend, None, None]: NetWitness backend instance
    """

    return NetWitnessBackend()


def test_netwitness_and_expression(netwitness_backend: NetWitnessBackend):
    """Basic test for an and expression"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(
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
        SigmaCollection.from_yaml(
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
        SigmaCollection.from_yaml(
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
        SigmaCollection.from_yaml(
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
        SigmaCollection.from_yaml(
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

    assert conversion_result == ["fieldA = 'valueA' || fieldA = 'valueB' || fieldA begins 'valueC'"]


def test_netwitness_regex_query(netwitness_backend: NetWitnessBackend):
    """Test conversion with basic regex for a value"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(
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


def test_netwitness_cidr_query(netwitness_backend: NetWitnessBackend):
    """Test basic query with cidr modifier"""

    conversion_result: str = netwitness_backend.convert(
        SigmaCollection.from_yaml(
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
