"""Mappings of identifier to backends used by pySigma"""

from .netwitness import NetWitnessBackend  # pylint:disable=import-self

# Mapping between backend identifiers and classes. This is used by the pySigma plugin system to
# recognize backends and expose them with the identifier.
backends = {
    "netwitness": NetWitnessBackend,
}
