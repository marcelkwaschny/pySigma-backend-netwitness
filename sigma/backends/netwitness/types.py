"""Custom types for the NetWitness backend"""

from typing import Optional

from sigma.types import SigmaString


class SigmaNetWitnessString(SigmaString):
    """Extension of sigma string which supports for more configuration options"""

    quote: bool

    def __init__(self, s: Optional[str] = None, quote: bool = True):
        super().__init__(s)
        self.quote = quote
