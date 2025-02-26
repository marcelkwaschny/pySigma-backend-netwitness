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
                for entry in val.values:
                    entry = SigmaString(str(entry))
                return val
            return SigmaString(str(val))
        if self.target_type == "num":
            try:
                if isinstance(val, SigmaExpansion):
                    for entry in val.values:
                        float_value = float(str(entry))
                        if float_value.is_integer():
                            entry = SigmaNumber(int(str(entry)))
                        else:
                            entry = SigmaNumber(float(str(entry)))
                    return val

                float_value = float(str(val))
                if float_value.is_integer():
                    return SigmaNumber(int(str(val)))

                return SigmaNumber(float_value)
            except SigmaValueError as error:
                raise SigmaValueError(f"Value '{val}' can't be converted to number for {str(self)}") from error

        return val
