"""Custom transformations for the NetWitness backend"""

from dataclasses import dataclass
from typing import Literal, Optional, Union

from sigma.exceptions import SigmaValueError
from sigma.processing.transformations import StringValueTransformation, ValueTransformation
from sigma.types import SigmaExpansion, SigmaNumber, SigmaString, SigmaType

from sigma.backends.netwitness.types import SigmaNetWitnessString


@dataclass
class UnquoteStringTransformation(StringValueTransformation):
    """Transformation to unquote a string. This is useful for ip addresses as these
    have to be unquoted in NetWitness in order to be searchable.
    """

    def apply_string_value(self, field: str, val: SigmaString) -> Optional[SigmaString]:
        return SigmaNetWitnessString(s=val.original, quote=False)


@dataclass
class CustomConvertTypeTransformation(ValueTransformation):
    """
    Convert type of value. The conversion into strings and numbers is currently supported.
    """

    target_type: Literal["str", "num"]

    def apply_value(self, field: str, val: SigmaType) -> Union[SigmaString, SigmaNumber, SigmaExpansion]:
        if self.target_type == "str":
            if isinstance(val, SigmaExpansion):
                for i, entry in enumerate(val.values):
                    val.values[i] = SigmaString(str(entry))

                return val

            return SigmaString(str(val))
        if self.target_type == "num":
            try:
                if isinstance(val, SigmaExpansion):
                    for i, entry in enumerate(val.values):
                        val.values[i] = SigmaNumber(str(entry))  # type: ignore[arg-type]

                    return val

                return SigmaNumber(str(val))  # type: ignore[arg-type]
            except SigmaValueError as error:
                raise SigmaValueError(f"Value '{val}' can't be converted to number for {str(self)}") from error

        return val
