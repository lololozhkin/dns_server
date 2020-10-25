import socket
import threading
from DnsPacketParser import DnsPacket
from RecordClass import RecordClass
from RecordType import RecordType
from ResourceRecord import ResourceRecord
from Query import Query
from DnsPacketComposer import DnsPacketComposer, generate_flags
import random
from utils import get_str_ip_from_bytes, get_ip_in_bytes_from_string


ROOT_DNS = '198.41.0.4'
DNS_PORT = 53


def make_request(req_ip, req_domain, sock):
    query = Query(req_domain.encode())
    to_send = DnsPacketComposer([query],
                                flags=generate_flags(),
                                id=random.randint(0, 0xFFFF))
    sock.sendto(to_send.compose_packet(), (req_ip, DNS_PORT))

    data, _ = sock.recvfrom(10000)

    return DnsPacket(data)


def get_ip(req_ip, req_domain, sock):
    response = make_request(req_ip, req_domain, sock)
    additional_with_ip = list(
        filter(lambda x: x.r_type == RecordType.A, response.additional))

    if len(response.answers):
        return get_str_ip_from_bytes(response.answers[0].data)

    if len(additional_with_ip):
        ip = get_str_ip_from_bytes(additional_with_ip[0].data)
        return get_ip(ip, req_domain, sock)
    else:
        ns_authorities = list(
            filter(lambda x: x.r_type == RecordType.NS, response.authorities))

        if len(ns_authorities):
            ns = ns_authorities[0].data.decode()
            authority_ip = get_ip(ROOT_DNS, ns, sock)
            return get_ip(authority_ip, req_domain, sock)


def serve_client(sock, query, addr):
    socket_for_dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packet = DnsPacket(query)
    req_id = packet.id

    if not len(packet.queries):
        sock.sendto(DnsPacketComposer(id=req_id).compose_packet(), addr)
        return
    domain = packet.queries[0].name

    ip = get_ip(ROOT_DNS, domain.decode(), socket_for_dns)
    response_packet = DnsPacketComposer(id=req_id)
    if ip is not None:
        response = ResourceRecord(domain, data=get_ip_in_bytes_from_string(ip))
        response_packet.add_answer(response)

    response_packet.set_flags(generate_flags(qa=1))
    sock.sendto(response_packet.compose_packet(), addr)


def main():
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.bind(('127.0.0.1', 13337))

    threads = set()
    while True:
        for th in list(threads):
            if not th.is_alive():
                th.join()
                threads.remove(th)

        data, addr = listen_sock.recvfrom(1024)

        th = threading.Thread(
            target=lambda: serve_client(listen_sock, data, addr))
        threads.add(th)
        th.daemon = True
        th.start()


if __name__ == '__main__':
    main()
