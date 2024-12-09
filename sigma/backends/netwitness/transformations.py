"""Custom transformations for the netwitness backend"""

from dataclasses import dataclass
from typing import Optional

from sigma.processing.transformations import StringValueTransformation
from sigma.types import SigmaString

from sigma.backends.netwitness.types import SigmaNetWitnessString


@dataclass
class UnquoteStringTransformation(StringValueTransformation):
    """Transformation to unquote a string. This is useful for ip addresses as these
    have to be unquoted in netwitness in order to be searchable.
    """

    def apply_string_value(self, field: str, val: SigmaString) -> Optional[SigmaString]:
        return SigmaNetWitnessString(s=val.original, quote=False)
