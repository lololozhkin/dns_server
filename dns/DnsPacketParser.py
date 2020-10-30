from RecordType import RecordType
from ResourceRecord import ResourceRecord
from Query import Query
from utils import generate_q_name_from_normal_name


def get_bit_slice(l, r, num):
    return ((num << l) & 0xFFFF) >> (l + 16 - r - 1)


class DnsPacket:
    def __init__(self, data: bytes):
        self._data = data
        self._header = data[:12]

        self._id = int.from_bytes(self._header[:2], 'big')
        self._flags = int.from_bytes(self._header[2:4], 'big')
        self._qd_count = int.from_bytes(self._header[4:6], 'big')
        self._ans_count = int.from_bytes(self._header[6:8], 'big')
        self._ns_count = int.from_bytes(self._header[8:10], 'big')
        self._ar_count = int.from_bytes(self._header[10:12], 'big')

        self._queries, ind = self._read_all_records(
            self._parse_query,
            self._qd_count,
            12)
        self._answers, ind = self._read_all_records(
            self._parse_resource_record,
            self._ans_count,
            ind)
        self._authority, ind = self._read_all_records(
            self._parse_resource_record,
            self._ns_count,
            ind)
        self._additional, _ = self._read_all_records(
            self._parse_resource_record,
            self._ar_count,
            ind)

    @property
    def id(self):
        return self._id

    @property
    def flags(self):
        return self._flags

    @property
    def qd_count(self):
        return self._qd_count

    @property
    def ans_count(self):
        return self._ans_count

    @property
    def ns_count(self):
        return self._ns_count

    @property
    def ar_count(self):
        return self._ar_count

    @property
    def is_query(self):
        return get_bit_slice(0, 0, self._flags) == 0

    @property
    def is_response(self):
        return not self.is_query

    @property
    def opt_code(self):
        return get_bit_slice(1, 4, self._flags)

    @property
    def is_authority(self):
        return bool(get_bit_slice(5, 5, self._flags))

    @property
    def truncated(self):
        return bool(get_bit_slice(6, 6, self._flags))

    @property
    def rd(self):
        return bool(get_bit_slice(7, 7, self._flags))

    @property
    def recursion_able(self):
        return bool(get_bit_slice(8, 8, self._flags))

    @property
    def r_code(self):
        return get_bit_slice(11, 15, self._flags)

    @property
    def queries(self):
        return self._queries

    @property
    def authorities(self):
        return self._authority

    @property
    def answers(self):
        return self._answers

    @property
    def additional(self):
        return self._additional

    def _read_all_records(self, parse_func, count, start):
        cur_ind = start
        ans = []
        for i in range(count):
            parsed_obj, ind = parse_func(cur_ind)
            ans.append(parsed_obj)
            cur_ind = ind

        return ans, cur_ind

    def _parse_query(self, start):
        name, name_end = self._parse_name_and_find_end(start)
        q_type = int.from_bytes(self._data[name_end:name_end + 2], 'big')
        q_class = int.from_bytes(self._data[name_end + 2:name_end + 4], 'big')
        return Query(name, q_type, q_class), name_end + 4

    def _parse_resource_record(self, start):
        name, name_end = self._parse_name_and_find_end(start)
        r_type = int.from_bytes(self._data[name_end:name_end + 2], 'big')
        r_class = int.from_bytes(self._data[name_end + 2:name_end + 4], 'big')
        ttl = int.from_bytes(self._data[name_end + 4:name_end + 8], 'big')
        data_length = int.from_bytes(
            self._data[name_end + 8:name_end + 10],
            'big')
        data = self._data[name_end + 10: name_end + 10 + data_length]

        record = ResourceRecord(name, r_type, r_class, ttl, data)
        if record.r_type == RecordType.NS:
            record.data, _ = self._parse_name_and_find_end(name_end + 10)

        return record, name_end + data_length + 10

    def _parse_name_and_find_end(self, start: int):
        parts = []
        name_end = start
        last_end = start

        while True:
            if self._data[last_end] == 0:
                break

            name_type = self._data[last_end] >> 6
            if name_type == 0b00:
                cur_length = self._data[last_end]
                parts.append(
                    self._data[last_end + 1:last_end + 1 + cur_length])
                last_end = last_end + cur_length + 1
            else:
                link = ((((self._data[last_end] << 2) & 0xFF) << 6)
                        | self._data[last_end + 1])
                name_end = max(name_end, last_end + 1)
                last_end = link

            name_end = max(name_end, last_end)

        return b'.'.join(parts), name_end + 1
