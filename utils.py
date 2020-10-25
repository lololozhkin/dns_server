def generate_q_name_from_normal_name(name):
    if name[-1] != b'.':
        name += b'.'

    return b''.join(
        map(lambda x: len(x).to_bytes(1, 'big') + x, name.split(b'.')))


def get_str_ip_from_bytes(bytes_ip):
    return '.'.join(map(str, bytes_ip))


def get_ip_in_bytes_from_string(str_ip):
    return b''.join(int(x).to_bytes(1, 'big') for x in str_ip.split('.'))
