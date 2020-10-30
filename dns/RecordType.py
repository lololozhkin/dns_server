from enum import Enum


class RecordType(Enum):
    A = 1
    NS = 2
    MX = 15
    AAAA = 28
    OPT = 41
    OTHER = 255


def get_record_type(num_type):
    try:
        return RecordType(num_type)
    except ValueError:
        return RecordType.OTHER
