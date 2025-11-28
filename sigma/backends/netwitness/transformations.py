"""Custom transformations for the NetWitness backend"""

from dataclasses import dataclass
from importlib.metadata import version
from typing import Literal

from packaging.version import Version
from sigma.exceptions import SigmaValueError
from sigma.types import SigmaExpansion, SigmaNumber, SigmaString, SigmaType

from sigma.backends.netwitness.types import SigmaNetWitnessString

if Version(version("pysigma")) >= Version("1.0.0"):
    from sigma.processing.transformations.base import (  # type: ignore[no-redef,attr-defined]
        StringValueTransformation,
        ValueTransformation,
    )
else:
    from sigma.processing.transformations import (  # type: ignore[no-redef,attr-defined]
        StringValueTransformation,
        ValueTransformation,
    )


@dataclass
class UnquoteStringTransformation(StringValueTransformation):
    """Transformation to unquote a string. This is useful for ip addresses as these
    have to be unquoted in NetWitness in order to be searchable.
    """

    def apply_string_value(self, field: str | None, val: SigmaString) -> SigmaNetWitnessString:  # noqa: ARG002
        """Applies the transformation on a given SigmaString and sets quote to False so
        that the value will be without quotes

        Args:
            field (str | None): Field
            val (SigmaString): Value

        Returns:
            SigmaString | None: _description_
        """

        return SigmaNetWitnessString(s=val.original, quote=False)


@dataclass
class CustomConvertTypeTransformation(ValueTransformation):
    """Convert type of value. The conversion into strings and numbers is currently supported."""

    target_type: Literal["str", "num"]

    def apply_value(self, field: str | None, val: SigmaType) -> SigmaType:  # noqa: ARG002
        """Transform a given value to the desired target_type

        Args:
            field (str | None): Field
            val (SigmaType): Value

        Raises:
            SigmaValueError: If the value couldn't be transformed

        Returns:
            SigmaType: Transformed value
        """

        if self.target_type == "str":
            if isinstance(val, SigmaExpansion):
                for i, entry in enumerate(val.values):
                    val.values[i] = SigmaString(str(entry))
            if isinstance(val, SigmaNumber):
                val = SigmaString(str(val))

        if self.target_type == "num":
            try:
                if isinstance(val, SigmaExpansion):
                    for i, entry in enumerate(val.values):
                        val.values[i] = SigmaNumber(str(entry))  # type: ignore[arg-type]
                if isinstance(val, SigmaString):
                    val = SigmaNumber(str(val))  # type: ignore[arg-type]
            except SigmaValueError as error:
                msg = f"Value '{val}' can't be converted to number for {self!s}"
                raise SigmaValueError(msg) from error

        return val
