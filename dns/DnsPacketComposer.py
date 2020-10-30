def generate_flags(
        qa=0,
        opcode=0,
        aa=0,
        tc=0,
        rd=1,
        ra=0,
        z=0,
        r_code=0):
    flag = 1
    flag = flag << 1 | qa
    flag = flag << 4 | opcode
    flag = flag << 1 | aa
    flag = flag << 1 | tc
    flag = flag << 1 | rd
    flag = flag << 1 | ra
    flag = flag << 3 | z
    flag = flag << 4 | r_code

    return (flag & 0xFFFF).to_bytes(2, 'big')


class DnsPacketComposer:
    def __init__(self,
                 requests=None,
                 answers=None,
                 authorities=None,
                 additional=None,
                 flags=b'\xff\xff',
                 id=1337):
        self._requests = [] if requests is None else requests
        self._answers = [] if answers is None else answers
        self._authorities = [] if authorities is None else authorities
        self._additional = [] if additional is None else additional
        self._flags = flags
        self._id = id

    def add_request(self, request):
        self._requests.append(request)

    def add_answer(self, answer):
        self._answers.append(answer)

    def add_authority(self, authority):
        self._authorities.append(authority)

    def add_additional(self, additional):
        self._additional.append(additional)

    def set_flags(self, flags):
        self._flags = flags

    def compose_packet(self):
        header = (self._id.to_bytes(2, 'big')
                  + self._flags
                  + len(self._requests).to_bytes(2, 'big')
                  + len(self._answers).to_bytes(2, 'big')
                  + len(self._authorities).to_bytes(2, 'big')
                  + len(self._additional).to_bytes(2, 'big')
                  )
        questions = b''.join(
            map(lambda req: req.generate_query_in_bytes(),
                self._requests))
        answers = b''.join(
            map(lambda x: x.generate_resource_record_in_bytes(),
                self._answers))
        authorities = b''.join(
            map(lambda x: x.generate_resource_record_in_bytes(),
                self._authorities))
        additional = b''.join(
            map(lambda x: x.generate_resource_record_in_bytes(),
                self._additional))

        return (header
                + questions
                + answers
                + authorities
                + additional)
