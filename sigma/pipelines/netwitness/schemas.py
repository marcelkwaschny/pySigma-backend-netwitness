"""Module for schemas used by NetWitness processing pipelines"""

from enum import IntEnum


class PipelinePriority(IntEnum):
    """Enum to define priorities for processing pipelines"""

    FIRST = 1
    SECOND = 2
    THIRD = 3
    LAST = 99
