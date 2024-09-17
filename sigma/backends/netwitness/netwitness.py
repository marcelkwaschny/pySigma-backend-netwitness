"""Module for the pySigma NetWitness backend"""

import re
from collections import defaultdict
from typing import Any, ClassVar, Dict, Optional, Pattern, Tuple, Union

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaConversionError
from sigma.types import (
    SigmaCompareExpression,
    SigmaExpansion,
    SigmaNumber,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)


class NetWitnessBackend(TextQueryBackend):
    """NetWitness backend."""

    name: ClassVar[str] = "netwitness backend"
    formats: ClassVar[Dict[str, str]] = {
        "default": "Plain netwitness queries",
    }
    # TODO: does the backend requires that a processing pipeline is provided? This information can be used by user
    # interface programs like Sigma CLI to warn users about inappropriate usage of the backend.
    requires_pipeline: ClassVar[bool] = False

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    # precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
    #     ConditionNOT,
    #     ConditionAND,
    #     ConditionOR
    # )
    group_expression: ClassVar[Optional[str]] = (
        "({expr})"  # Expression for precedence override grouping as format string with {expr} placeholder
    )
    parenthesize: bool = True

    # Generated query tokens
    token_separator: str = " "  # separator inserted between all boolean operators
    or_token: ClassVar[Optional[str]] = "||"
    and_token: ClassVar[Optional[str]] = "&&"
    not_token: ClassVar[Optional[str]] = "NOT"
    eq_token: ClassVar[Optional[str]] = " = "  # Token inserted between field and value

    # String output
    # Fields
    # Quoting

    # Character used to quote field characters if field_quote_pattern matches (or not, depending on
    # field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote: ClassVar[Optional[str]] = None
    # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation.
    # Field name is always quoted if pattern is not set.
    field_quote_pattern: ClassVar[Optional[Pattern[str]]] = re.compile("^\\w+$")
    # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).
    field_quote_pattern_negation: ClassVar[bool] = True

    # Values
    str_quote: ClassVar[str] = "'"  # string quoting character (added as escaping character)
    escape_char: ClassVar[Optional[str]] = "\\"  # Escaping character for special characrers inside string
    wildcard_multi: ClassVar[Optional[str]] = ""  # Character used as multi-character wildcard
    wildcard_single: ClassVar[Optional[str]] = ""  # Character used as single-character wildcard
    # add_escaped: ClassVar[str] = "\\"  # Characters quoted in addition to wildcards and string quote
    filter_chars: ClassVar[str] = ""  # Characters filtered
    bool_values: ClassVar[Dict[bool, Optional[str]]] = {  # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression: ClassVar[Optional[str]] = "{field} begins {value}"
    endswith_expression: ClassVar[Optional[str]] = "{field} ends {value}"
    contains_expression: ClassVar[Optional[str]] = "{field} contains {value}"
    wildcard_match_expression: ClassVar[Optional[str]] = (
        None  # Special expression if wildcards can't be matched with the eq_token operator
    )

    # Regular expressions
    # Regular expression query as format string with placeholders {field}, {regex}, {flag_x} where x
    # is one of the flags shortcuts supported by Sigma (currently i, m and s) and refers to the
    # token stored in the class variable re_flags.
    re_expression: ClassVar[Optional[str]] = "{field} regex '{regex}'"
    re_escape_char: ClassVar[Optional[str]] = "\\"  # Character used for escaping in regular expressions
    re_escape_escape_char: bool = True  # If True, the escape character is also escaped
    # If True, the flags are prepended as (?x) group at the beginning of the regular expression, e.g. (?i).
    # If this is not supported by the target, it should be set to False.
    re_flag_prefix: bool = True
    # Mapping from SigmaRegularExpressionFlag values to static string templates that are used in
    # flag_x placeholders in re_expression template.
    # By default, i, m and s are defined. If a flag is not supported by the target query language,
    # remove it from re_flags or don't define it to ensure proper error handling in case of appearance.
    re_flags: Dict[SigmaRegularExpressionFlag, str] = {
        SigmaRegularExpressionFlag.IGNORECASE: "i",
        SigmaRegularExpressionFlag.MULTILINE: "m",
        SigmaRegularExpressionFlag.DOTALL: "s",
    }

    # Case sensitive string matching expression. String is quoted/escaped like a normal string.
    # Placeholders {field} and {value} are replaced with field name and quoted/escaped string.
    case_sensitive_match_expression: ClassVar[Optional[str]] = "{field} casematch {value}"
    # Case sensitive string matching operators similar to standard string matching. If not provided,
    # case_sensitive_match_expression is used.
    case_sensitive_startswith_expression: ClassVar[Optional[str]] = "{field} casematch_startswith {value}"
    case_sensitive_endswith_expression: ClassVar[Optional[str]] = "{field} casematch_endswith {value}"
    case_sensitive_contains_expression: ClassVar[Optional[str]] = "{field} casematch_contains {value}"

    # CIDR expressions: define CIDR matching if backend has native support. Else pySigma expands
    # CIDR values into string wildcard matches.
    # CIDR expression query as format string with placeholders {field}, {value} (the whole CIDR value), {network}
    # (network part only), {prefixlen} (length of network mask prefix) and {netmask} (CIDR network mask only).
    cidr_expression: ClassVar[Optional[str]] = "{field} = {value}"

    # Numeric comparison operators
    # Compare operation query as format string with placeholders {field}, {operator} and {value}
    compare_op_expression: ClassVar[Optional[str]] = "{field} {operator} {value}"
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators: ClassVar[Optional[Dict[SigmaCompareExpression.CompareOperators, str]]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Expression for comparing two event fields
    # Field comparison expression with the placeholders {field1} and {field2} corresponding to left
    # field and right value side of Sigma detection item
    field_equals_field_expression: ClassVar[Optional[str]] = None
    # If regular field-escaping/quoting is applied to field1 and field2. A custom escaping/quoting can be
    # implemented in the convert_condition_field_eq_field_escape_and_quote method.
    field_equals_field_escaping_quoting: Tuple[bool, bool] = (
        True,
        True,
    )

    exists_token: ClassVar[Optional[str]] = "exists"
    not_exists_token: ClassVar[Optional[str]] = "!exists"

    # Null/None expressions
    # Expression for field has null value as format string with {field} placeholder for field name
    field_null_expression: ClassVar[Optional[str]] = f"{{field}} {not_exists_token} || {{field}} = '-'"

    # Field existence condition expressions.
    # Expression for field existence as format string with {field} placeholder for field name
    field_exists_expression: ClassVar[Optional[str]] = f"{{field}} {exists_token}"

    # Expression for field non-existence as format string with {field} placeholder for field name.
    # If not set, field_exists_expression is negated with boolean NOT.
    field_not_exists_expression: ClassVar[Optional[str]] = f"{{field}} {not_exists_token}"

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in: ClassVar[bool] = True  # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = False  # Convert AND as in-expression
    # Values in list can contain wildcards. If set to False (default) only
    # plain values are converted into in-expressions.
    in_expressions_allow_wildcards: ClassVar[bool] = True
    # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    field_in_list_expression: ClassVar[Optional[str]] = "{field} {op} {list}"
    or_in_operator: ClassVar[Optional[str]] = (
        "="  # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    )
    and_in_operator: ClassVar[Optional[str]] = (
        None  # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    )
    list_separator: ClassVar[Optional[str]] = ","  # List element separator

    # Value not bound to a field
    unbound_value_str_expression: ClassVar[Optional[str]] = (
        "'{value}'"  # Expression for string value not bound to a field as format string with placeholder {value}
    )
    unbound_value_num_expression: ClassVar[Optional[str]] = (
        "{value}"  # Expression for number value not bound to a field as format string with placeholder {value}
    )
    # Expression for regular expression not bound to a field as format string with
    # placeholder {value} and {flag_x} as described for re_expression
    unbound_value_re_expression: ClassVar[Optional[str]] = "_=~{value}"

    # Query finalization: appending and concatenating deferred query part
    deferred_start: ClassVar[Optional[str]] = "\n| "  # String used as separator between main query and deferred parts
    deferred_separator: ClassVar[Optional[str]] = "\n| "  # String used to join multiple deferred query parts
    deferred_only_query: ClassVar[Optional[str]] = (
        "*"  # String used as query if final query only contains deferred expression
    )

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of NOT conditions

        Args:
            cond (ConditionNOT): NOT Condition object that should be converted
            state (ConversionState): State of the conversion

        Raises:
            NotImplementedError: If something isn't supported by the backend

        Returns:
            Union[str, DeferredQueryExpression]: Generated query
        """

        if self.not_token is None or self.group_expression is None:
            raise NotImplementedError("Values for 'not_token' and 'group_expression' are needed to be set")

        if not cond.args:
            raise ValueError("Given condition contains no arguments")

        arg = cond.args[0]

        try:
            if arg.__class__ in self.precedence:  # group if AND or OR condition is negated
                return self.not_token + self.token_separator + self.convert_condition_group(arg, state)  # type: ignore

            expr = self.convert_condition(arg, state)  # type: ignore
            if isinstance(expr, DeferredQueryExpression):  # negate deferred expression and pass it to parent
                return expr.negate()

            # convert negated expression to string
            return self.not_token + self.token_separator + self.group_expression.format(expr=expr)
        except TypeError as error:
            raise NotImplementedError("Operator 'not' isn't supported by the backend") from error

    def convert_condition_field_eq_expansion(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        """Converting expansion conditions like windash, contains, base64 e.g.

        Args:
            cond (ConditionFieldEqualsValueExpression): Condition that should be converted
            state (ConversionState): State of the conversion

        Raises:
            ValueError: If the method will be called with a condition that isn't a 'SigmaExpansion'

        Returns:
            Any: Query as string or DeferredQueryExpression
        """

        if not isinstance(cond.value, SigmaExpansion):
            raise ValueError("Only conditions with SigmaExpansion values are allowed for this method")

        or_cond = ConditionOR(
            [ConditionFieldEqualsValueExpression(cond.field, value) for value in cond.value.values],
            cond.source,
        )

        if self.decide_convert_condition_as_in_expression(or_cond, state):
            return self.convert_condition_as_in_expression(or_cond, state)

        return self.convert_condition_or(or_cond, state)

    def decide_convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> bool:
        """Decide if an OR or AND expression should be converted as "field in (value list)" or as plain expression.

        Args:
            cond (Union[ConditionOR, ConditionAND]): Condition that is converted for which the decision has to be made
            state (ConversionState): Current conversion state

        Returns:
            bool: True if in-expression should be generated, else False
        """

        if (
            not self.convert_or_as_in
            and isinstance(cond, ConditionOR)
            or not self.convert_and_as_in
            and isinstance(cond, ConditionAND)
        ):
            return False

        # All arguments of the given condition must reference a field
        if not all((isinstance(arg, ConditionFieldEqualsValueExpression) for arg in cond.args)):
            return False

        # Build a set of all fields appearing in condition arguments
        fields = {arg.field for arg in cond.args if isinstance(arg, ConditionFieldEqualsValueExpression)}
        # All arguments must reference the same field
        if len(fields) != 1:
            return False

        # All argument values must be strings or numbers
        if not all(
            isinstance(arg.value, (SigmaString, SigmaNumber, SigmaExpansion))
            for arg in cond.args
            if isinstance(arg, (ConditionValueExpression, ConditionFieldEqualsValueExpression))
        ):
            return False

        # Check for plain strings if wildcards are not allowed for string expressions.
        if not self.in_expressions_allow_wildcards and any(
            arg.value.contains_special()
            for arg in cond.args
            if isinstance(arg, (ConditionValueExpression, ConditionFieldEqualsValueExpression))
            and isinstance(arg.value, SigmaString)
        ):
            return False

        # All checks passed, expression can be converted to in-expression
        return True

    def is_contains(self, arg: Union[ConditionFieldEqualsValueExpression, ConditionValueExpression]) -> bool:
        """Checks if an given argument is a contains expression

        Args:
            arg (Union[ConditionFieldEqualsValueExpression, ConditionValueExpression]): Argument to check

        Returns:
            bool: True if contains statement, False otherwise
        """

        if (
            isinstance(arg.value, SigmaString)
            and len(arg.value.s) == 3
            and isinstance(arg.value.s[0], SpecialChars)
            and isinstance(arg.value.s[2], SpecialChars)
        ):
            return True

        return False

    def is_begins(self, arg: Union[ConditionFieldEqualsValueExpression, ConditionValueExpression]) -> bool:
        """Checks if an given argument is a begins expression

        Args:
            arg (Union[ConditionFieldEqualsValueExpression, ConditionValueExpression]): Argument to check

        Returns:
            bool: True if begins statement, False otherwise
        """

        if isinstance(arg.value, SigmaString) and len(arg.value.s) == 2 and isinstance(arg.value.s[1], SpecialChars):
            return True

        return False

    def is_ends(self, arg: Union[ConditionFieldEqualsValueExpression, ConditionValueExpression]) -> bool:
        """Checks if an given argument is an ends expression

        Args:
            arg (Union[ConditionFieldEqualsValueExpression, ConditionValueExpression]): Argument to check

        Returns:
            bool: True if ends statement, False otherwise
        """

        if isinstance(arg.value, SigmaString) and len(arg.value.s) == 2 and isinstance(arg.value.s[0], SpecialChars):
            return True

        return False

    def unpack_condition_if_necessary(self, cond: Union[ConditionOR, ConditionAND]) -> Union[ConditionOR, ConditionAND]:
        """This method checks if a condition needs unpacking. If the condition contains arguments with values
        that have the SigmaExpansion type unpacking is necessary for netwitness. This will convert the SigmaExpansion
        value into normal ConditionFieldEqualsValueExpression which then can be used to turn into a list. Therefore
        queries will get shorter.

        Args:
            cond (Union[ConditionOR, ConditionAND]): Condition that should be unpacked if necessary

        Returns:
            Union[ConditionOR, ConditionAND]: Updated condition or unchanged if not necessary
        """

        if isinstance(cond, ConditionAND):
            return cond

        updated_condition: ConditionOR = ConditionOR(args=[])

        for arg in cond.args:
            if isinstance(arg, ConditionFieldEqualsValueExpression) and isinstance(arg.value, SigmaExpansion):
                updated_condition.args.extend(
                    [ConditionFieldEqualsValueExpression(arg.field, value) for value in arg.value.values]
                )
            else:
                updated_condition.args.append(arg)

        return updated_condition

    def convert_or_expressions_into_sub_expressions(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> list[Union[str, DeferredQueryExpression]]:
        """Converts a condition into sub expressions. This is used to generate smaller expressions
        for netwitness. Generally expressions like fieldA = 'foo' || fieldA = 'bar' can be summarized
        as fieldA = 'foo','bar'. This also works for modifiers like contains, begins, ends e.g. but for
        them the standard implementation of pySigma doesn't generates lists. So this is the implementation
        for that. The implementation also supports multiple modifiers in the condition which will then
        get seperatly summarized.

        Args:
            cond (Union[ConditionOR, ConditionAND]): Conditions that should be used for the conversion
            state (ConversionState): Conversion state that is passed to sub methods

        Raises:
            SigmaConversionError: If field_in_list_expression is not set
            SigmaConversionError: If or_in_operator is not set

        Returns:
            list[Union[str, DeferredQueryExpression]]: List of generated sub expressions
        """

        if not self.field_in_list_expression:
            raise SigmaConversionError("Value for 'field_in_list_expression' isn't set in the backend")

        if not self.or_in_operator:
            raise SigmaConversionError("Value for 'or_in_operator' isn't set in the backend")

        result: dict[str, list[Union[ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression]]] = (
            defaultdict(list[Union[ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression]])
        )

        for arg in cond.args:
            if not isinstance(arg, (ConditionFieldEqualsValueExpression, ConditionValueExpression)):
                continue

            if self.is_contains(arg):
                result["contains"].append(arg)
            elif self.is_begins(arg):
                result["begins"].append(arg)
            elif self.is_ends(arg):
                result["ends"].append(arg)
            else:
                result["or"].append(arg)

        expressions: list[Union[str, DeferredQueryExpression]] = []

        for modifier, args in result.items():
            if not args:
                continue

            sub_expression: Union[str, DeferredQueryExpression] = super().convert_condition_as_in_expression(
                cond=ConditionOR(args=args), state=state
            )

            if isinstance(sub_expression, str) and modifier not in ["or"]:
                sub_expression = sub_expression.replace(self.or_in_operator, modifier)

            expressions.append(sub_expression)

        return expressions

    def convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of OR or AND conditions into "field in (value list)" expressions

        Args:
            cond (Union[ConditionOR, ConditionAND]): OR or AND condition
            state (ConversionState): State of the conversion

        Raises:
            NotImplementedError: If a DeferredQueryExpression is used

        Returns:
            Union[str, DeferredQueryExpression]: Expression
        """

        cond = self.unpack_condition_if_necessary(cond)
        sub_expressions = self.convert_or_expressions_into_sub_expressions(cond, state)

        if sub_expressions and all(isinstance(entry, str) for entry in sub_expressions):
            return f" {self.or_token} ".join([entry for entry in sub_expressions if isinstance(entry, str)])

        raise NotImplementedError("DeferredQueryExpression type is not implemented yet")
