from enum import Enum


class RecordClass(Enum):
    IN = 1
    CH = 3
    UDP_PAYLOAD_SIZE = 4096
    OTHER = 0xFFFF


def get_record_class(num_type):
    try:
        return RecordClass(num_type)
    except ValueError:
        return RecordClass.OTHER
