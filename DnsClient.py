import socket
import random
import time
import argparse
import signal


class TimeoutException(Exception):
    pass


def timeout_handler(signum, frame):
    raise TimeoutException


signal.signal(signal.SIGALRM, timeout_handler)


class Client:

    def __init__(self, params):
        self.timeout = params.timeout
        self.max_retries = params.max_retries
        self.port = params.port
        if params.mx:
            self.qtype = '000f'
        elif params.ns:
            self.qtype = '0002'
        else:
            self.qtype = '0001'
        self.server = params.server
        self.name = params.name.strip()
        self.read_buffer = 512

        self.website_name = None
        self.request_type = None
        self.response_code = None
        self.ip_address = ''

    def buildQuery(self):
        data = ''

        # ID
        id_value = random.randint(0, 2 ** 16 - 1)
        id = str(hex(id_value))[2:].zfill(4)
        data += id

        # Flags
        data += '0100'

        # QDCOUNT
        data += '0001'

        # ANCOUNT, NSCOUNT, ARCOUNT
        data += '0000'
        data += '0000'
        data += '0000'

        for i, word in enumerate(self.name.split('.')):
            if len(word) < 16:
                data += "0" + hex(len(word))[2:]
            else:
                data += hex(len(word))[2:]

            data += "".join([hex(ord(c))[2:] for c in word])
        data += "00"

        # QTYPE, QCLASS
        data += self.qtype
        data += "0001"

        data = bytes.fromhex(data)
        return data

    def handleResponseCode(self, response_code):
        message = None
        is_valid = True
        if response_code == 1:
            is_valid = False
            message = 'Format error: the name server was unable to interpret the query'
        elif response_code == 2:
            is_valid = False
            message = 'Server failure: the name server was unable to process \
                this query due to a problem with the name server'
        elif response_code == 3:
            is_valid = False
            message = 'Name error: meaningful only for responses from an authoritative \
                name server, this code signifies that the domain name referenced in the query does not exist'
        elif response_code == 4:
            is_valid = False
            message = 'Not implemented: the name server does not support the requested kind of query'
        elif response_code == 5:
            is_valid = False
            message = 'Refused: the name server refuses to perform the requested operation for policy reasons'

        return is_valid, message

    def decodeQName(self, data, start, end):
        website_name = []
        word = ''
        word_length = data[start]
        count = 1
        total_count = 1
        while total_count < end:
            word += chr(int(data[count+start:count+start+1].hex(), 16))
            count += 1
            total_count += 1

            if count == word_length + 1:
                if data[count + start] == 0:
                    break
                website_name.append(word)
                word = ''
                next_byte = data[count+start:count+start+1].hex()
                if next_byte[0] == 'c':
                    count += 1
                    total_count += 1
                    compressed_name, _ = self.decodeQName(data, int(data[count + start:count + start + 1].hex(), 16), len(data))
                    website_name += compressed_name.split('.')
                    start += count
                    count = 1
                if count + start >= len(data):
                    break
                word_length = data[count + start]
                start += count
                total_count += 1
                count = 1
        if word:
            website_name.append(word)
        website_name = '.'.join(website_name)
        return website_name, start+count+1

    def extractResponse(self, data):
        response_code = int(data[3:4].hex()[1], 16)
        is_valid, message = self.handleResponseCode(response_code)

        website_name, index = self.decodeQName(data, 12, len(data))
        self.website_name = website_name

        qtype_index = index

        request_type = data[qtype_index:qtype_index+2].hex()
        if request_type == '0001':
            self.request_type = 'Type-A response'
        elif request_type == '0002':
            self.request_type = 'Type-NS response'
        elif request_type == '0005':
            self.request_type = 'Type-CNAME response'
        elif request_type == '000f':
            self.request_type = 'Type-MX response'

        rd_length_index = qtype_index+14
        if is_valid:
            response_length = int(data[rd_length_index:rd_length_index+2].hex(), 16)
            r_data_index = rd_length_index+2
            if request_type == '0001':
                ip_address = []
                for i in range(response_length):
                    ip_address.append(str(int(data[r_data_index + i:r_data_index + 1 + i].hex(), 16)))
                self.ip_address = '.'.join(ip_address)
            elif request_type == '0002':
                while r_data_index < len(data) - 1:
                    # fix response_length
                    decoded_name, r_data_index = self.decodeQName(data, r_data_index, response_length)
                    self.ip_address += decoded_name + ' '
                    r_data_index += 10
                self.ip_address.strip()
            elif request_type == '000f':
                decoded_name, _ = self.decodeQName(data, r_data_index+2, len(data))
                self.ip_address = decoded_name

        return is_valid, message

    def makeQuery(self):
        for i in range(self.max_retries + 1):
            try:
                signal.alarm(self.timeout)

                start_time = time.time()
                query = self.buildQuery()

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(query, (self.server, self.port))

                data, address = sock.recvfrom(self.read_buffer)
                is_valid, message = self.extractResponse(data)

                if is_valid:
                    print('')
                    print('----------RESULT--------------')
                    print('DnsClient sending request for: ', self.website_name)
                    print('Server: ', self.ip_address)
                    print('Request type: ', self.request_type)
                    print('Response received after {time} seconds ({num_retries} retries)'.format(
                        time=time.time() - start_time, num_retries=i))
                    print('------------------------------')
                    print('')
                else:
                    print(message)
                break

            except TimeoutException:
                continue


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Use this command line tool to query a DNS server')
    parser.add_argument("-t", "--timeout", nargs='?', type=int, default=5,
                        help="timeout(optional) gives how long to wait, in seconds, \
                            before retransmitting an unanswered query")
    parser.add_argument("-r", "--max-retries", nargs='?', type=int, default=3,
                        help="max-retries(optional) is the maximum number of times \
                             to retransmit an unanswered query before giving up.")
    parser.add_argument("-p", "--port", type=int, nargs='?', default=53,
                        help="port(optional) is the UDP port number of the DNS server")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-mx", action='store_true',
                       help='mx/ns flags (optional) indicate whether to send a MX (mail server) or \
                            NS (name server) query. At most one of these can be given, and if neither \
                            is given then the client should send a type A (IP address) query')
    group.add_argument("-ns", action='store_true')
    parser.add_argument("-s", "--server", type=str,
                        help="server (required) is the IPv4 address of the DNS server, in a.b.c.d. format")
    parser.add_argument("-n", "--name", type=str,
                        help="name (required) is the domain name to query for")

    params = parser.parse_args()
    client = Client(params)
    client.makeQuery()