"""Custom types for the NetWitness backend"""

from sigma.types import SigmaString


class SigmaNetWitnessString(SigmaString):
    """Extension of sigma string which supports for more configuration options"""

    quote: bool

    def __init__(self, s: str | None = None, quote: bool = True) -> None:  # noqa: FBT001, FBT002
        """Instantiates a new sigma netwitness string

        Args:
            s (str | None, optional): String. Defaults to None.
            quote (bool, optional): If the string should be quoted. Defaults to True.
        """

        super().__init__(s)
        self.quote = quote
