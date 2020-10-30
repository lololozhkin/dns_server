from RecordType import RecordType, get_record_type
from RecordClass import RecordClass, get_record_class
from utils import generate_q_name_from_normal_name


class Query:
    def __init__(self,
                 qname=b'',
                 query_type=RecordType.A,
                 query_class=RecordClass.IN):
        self._qname = qname
        self._type = get_record_type(query_type)
        self._class = get_record_class(query_class)

    def generate_query_in_bytes(self):
        q_name = generate_q_name_from_normal_name(self._qname)
        q_type = self._type.value.to_bytes(2, 'big')
        q_class = self._class.value.to_bytes(2, 'big')

        return q_name + q_type + q_class

    @property
    def name(self):
        return self._qname

    @property
    def q_type(self):
        return self._type

    @property
    def q_class(self):
        return self._class
