# This file contains the severity levels.
# We are using IntEnums for levels to make it easier to compare the severity levels and to sort findings by severity if needed.
# Also this is later used in calculating the overall severity of the report based on the findings.

from enum import IntEnum

class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    # Override the __str__ method to return the capitalized name of the severity level instead of the integer value.
    def __str__(self):
        return self.name.capitalize()