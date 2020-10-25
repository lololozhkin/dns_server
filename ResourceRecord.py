from RecordClass import RecordClass, get_record_class
from RecordType import RecordType, get_record_type
from utils import generate_q_name_from_normal_name


class ResourceRecord:
    def __init__(self,
                 qname=b'',
                 record_type=RecordType.A,
                 record_class=RecordClass.IN,
                 ttl=3600,
                 data=b''):
        self._qname = qname
        self._type = get_record_type(record_type)
        self._class = get_record_class(record_class)
        self._ttl = ttl
        self._data = data

    def generate_resource_record_in_bytes(self):
        q_name = generate_q_name_from_normal_name(self._qname)
        r_type = self._type.value.to_bytes(2, 'big')
        r_class = self._class.value.to_bytes(2, 'big')
        ttl = self._ttl.to_bytes(4, 'big')
        rd_length = len(self._data).to_bytes(2, 'big')
        
        return q_name + r_type + r_class + ttl + rd_length + self._data

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, new_data):
        self._data = new_data

    @property
    def name(self):
        return self._qname

    @property
    def r_type(self):
        return self._type

    @property
    def r_class(self):
        return self._class

    @property
    def ttl(self):
        return self._ttl
