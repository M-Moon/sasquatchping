#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import socketserver
import os
import sys
import struct
import time

# icmp constants
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_CODE = socket.getprotobyname('icmp')
ICMP_MAX_RECV_SIZE = 2048

def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=4)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=4, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: str) -> str:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): ttl=%d time=%.2f ms" % (packetLength, destinationHostname, destinationAddress, ttl, time))
        else:
            print("%d bytes from %s: ttl=%d time=%.2f ms" % (packetLength, destinationAddress, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))


class ICMPPing(NetworkApplication):

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
        # 1. Wait for the socket to receive a reply
        icmpSocket.settimeout(timeout)

        try:
            reply, addr = icmpSocket.recvfrom(ICMP_MAX_RECV_SIZE)
        except socket.timeout as msg:
            print("No data received from socket within timeout period. Message: " + str(msg))
            sys.exit(1)

        # 2. Once received, record time of receipt, otherwise, handle a timeout
        recv_time = time.time()
        
        # 4. Unpack the packet header for useful information, including the ID
        replyHeader = struct.unpack("BBHHH", reply[20:28]) # icmp header of the received packet, bottom of packet because of network byte-order
        replyBody = struct.unpack("BBHHHBBHII", reply[:20]) # body of the received packet

        #print(replyHeader)
        #print(replyBody)
        #print(self.own_id)
        
        # 5. Check that the ID matches between the request and reply
        if replyHeader[3] != self.own_id:
                print("Received packet ID does not match sent packet with sequence number " + self.seq_number)
                print("Ending program")
                sys.exit(1)
                
        # 6. Return recv time + packet size
        return (recv_time, len(reply), replyBody[5])

    def buildPacket(self, checksum=0):
        # header is request type (8), code (8), checksum (16), id (16), sequence_num (16)
        hdr = struct.pack("BBHHH",
                          ICMP_ECHO_REQUEST,
                          0,
                          checksum,
                          self.own_id,
                          self.seq_number)
        
        dummy_data = 32 * b'Q' # dummy data to fill out the rest of the packet so it's not just a header
        packet = hdr + dummy_data
        #print(len(hdr))
        
        return packet

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        # 1. Build ICMP header

        # dummy header
        packet = self.buildPacket()
        
        # 2. Checksum ICMP packet using given function
        checksum = self.checksum(packet)
        
        # 3. Insert checksum into packet
        packet = self.buildPacket(checksum)
        
        # 4. Send packet using socket
        try:
            icmpSocket.sendto(packet, (destinationAddress, 1)) #port doesn't matter for icmp message
        except socket.error as msg:
            print("Error sending icmp packet to destination. Error: " + str(msg))
            sys.exit(1)
            
        # 5. Record time of sending
        send_time = time.time()
        return send_time
        
    def doOnePing(self, destinationAddress, timeout=5):
        # 1. Create ICMP socket
        try:
                icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
        except socket.error as msg:
                print("Socket could not be created. Error: " + str(msg))
                sys.exit(1)
        
        # 2. Call sendOnePing function
        send_time = self.sendOnePing(icmpSocket, destinationAddress, self.own_id)
        
        # 3. Call receiveOnePing function
        recv_details = self.receiveOnePing(icmpSocket, destinationAddress, self.own_id, timeout)
        
        # 4. Close ICMP socket
        icmpSocket.close()

        send_time_ms = send_time * 1000
        recv_time_ms = recv_details[0] * 1000

        #print(recv_time_ms - send_time_ms)
        
        # 5. Return total network delay
        total_delay = recv_time_ms - send_time_ms
        ping_details = (total_delay, recv_details[1], recv_details[2])

        return ping_details

    def calcDelays(self, ping_details, min_delay, max_delay, avg_delay_details):
        delay = ping_details[0] # unpack delay time for use

        if min_delay == 0: # check if delay set or not
                min_delay = delay
        
        if delay < min_delay: # check if delay is lower than minimum delay
                min_delay = delay
        if delay > max_delay: # check if delay is higher than maximum delay
                max_delay = delay

        if avg_delay_details[0] == 0: # check if no delay recorded yet
                avg_delay_details[1] += 1
                avg_delay_details[0] = delay
        else:
                avg_delay_details[1] += 1
                avg_delay_details[0] += delay

        avg_delay = avg_delay_details[0] / avg_delay_details[1]

        return min_delay, avg_delay, max_delay, avg_delay_details

    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))

        self.own_id = os.getpid() & 0xFFFF
        self.seq_number = 1
        
        # 1. Look up hostname, resolving it to an IP address
        try:
                ip = socket.gethostbyname(args.hostname)
        except socket.gaierror as msg:
                print("gaierror: " + str(msg))
                sys.exit(1)

        # setting delay variables
        min_delay = 0.0
        avg_delay_details = [0.0, 0.0] # total delay and number of delays recorded
        avg_delay = 0.0
        max_delay = 0.0

        #print("IP = " + ip)
        #print("-"*32)
        
        # 2. Call doOnePing function, approximately every second
        while True:
            try:
                time.sleep(1)

                try:
                    ping_details = self.doOnePing(ip, args.timeout)
                except AttributeError:
                    ping_details = self.doOnePing(ip)

                min_delay, avg_delay, max_delay, avg_delay_details = self.calcDelays(ping_details, min_delay, max_delay, avg_delay_details)
                #print(self.min_delay, self.avg_delay, self.max_delay)
                
                # 3. Print out the returned delay (and other relevant details) using the printOneResult method
                self.printOneResult(ip, ping_details[1], ping_details[0], ping_details[2], args.hostname) #destAddr, packLen, delayTime, ttl, destHostName(optional)
                
                # 4. Continue this process until stopped
                self.seq_number += 1
            except KeyboardInterrupt:
                #print("\nProgram stopped: Keyboard interrupt.")
                #print("-"*32)
                self.printAdditionalDetails(0, min_delay, avg_delay, max_delay)
                sys.exit(1)


class Traceroute(NetworkApplication):

    def buildPacket(self, checksum=0):
        # header is request type (8), code (8), checksum (16), id (16), sequence_num (16)
        hdr = struct.pack("BBHHH",
                          ICMP_ECHO_REQUEST,
                          0,
                          checksum,
                          self.own_id,
                          self.seq_number)
        
        #dummy_data = 32 * b'Q' # dummy data to fill out the rest of the packet so it's not just a header
        
        return hdr

    def packetConstructWithChecksum(self):
        packet = self.buildPacket()
        checksum = self.checksum(packet)
        packet = self.buildPacket(checksum) # insert checksum
        return packet

    def checkIDMatches(self, header):
        if header[3] == self.own_id:
            #print("ID MATCHES")
            return
        else:
            #print("ICMP Reply packet ID does not match ICMP Request packet")
            return

    def makeICMPSocket(self):
        try:
                traceroute_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
        except socket.error as msg:
                print("ICMP socket could not be created. Error: " + str(msg))
                sys.exit(1)
        return traceroute_socket

    def makeUDPSocket(self):
        try:
                traceroute_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.getprotobyname('udp'))
        except socket.error as msg:
                print("UDP socket could not be created. Error: " + str(msg))
                sys.exit(1)
        return traceroute_socket

    def processPacket(self, packet):
        reply_length = len(packet)
        
        #Unpack the packet header for useful information
        reply_header = struct.unpack("BBHHH", packet[20:28]) # icmp header of the received packet, bottom of packet because of network byte-order
        reply_body = struct.unpack("BBHHHBBHII", packet[:20]) # body of the received packet

        return reply_header, reply_length

    def recvPing(self, traceroute_socket):
        try:
            recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE) # create new receiving socket - can be used whether icmp or udp used
            recv_socket.settimeout(self.timeout)

            reply, addr = recv_socket.recvfrom(ICMP_MAX_RECV_SIZE)

            recv_socket.close() # close receiving socket
        except socket.timeout:
            print("* * *")
            return -1

        recv_time = time.time() # record time of packet receival
        recv_header, packet_length = self.processPacket(reply)

        return recv_time, addr[0], packet_length, recv_header

    def sendPing(self, traceroute_socket, packet, dest_addr):
        try:
            traceroute_socket.sendto(packet, (dest_addr, 33434)) # using unprivileged port, 33434 to account for udp
        except socket.error as msg:
            print("Error sending icmp packet to destination. Error: " + str(msg))
            sys.exit(1)
            
        # record time of sending
        send_time = time.time()
        return send_time

    def handleResults(self, recv_addr, send_time, recv_time, packet_length, ttl):
        # converting time to milliseconds
        send_time_ms = send_time * 1000
        recv_time_ms = recv_time * 1000

        # calculating the total time
        total_time = recv_time_ms - send_time_ms

        #printOneResult(destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname: str)
        try: # resolving hostname
            recv_hostname = socket.gethostbyaddr(recv_addr)[0]
            self.printOneResult(recv_addr, packet_length, total_time, ttl, recv_hostname)
        except socket.herror: # if hostname cannot be resolved
            self.printOneResult(recv_addr, packet_length, total_time, ttl)

        return total_time

    def checkDestReached(self, recv_header):
        # checking if received icmp code is 0, meaning successful endpoint reply
        recv_type = recv_header[0]
        recv_code = recv_header[1]

        # icmp reply type 0 for successful icmp reply, udp reply type 3 for successful udp reply
        if recv_type == 0 or recv_type == 3:
            dest_reached = True
            self.checkIDMatches(recv_header)
        else:
            dest_reached = False

        return dest_reached

    def calcDelays(self, delay, min_delay, max_delay, avg_delay_details):
        if min_delay == 0: # check if delay set or not
                min_delay = delay
        
        if delay < min_delay: # check if delay is lower than minimum delay
                min_delay = delay
        if delay > max_delay: # check if delay is higher than maximum delay
                max_delay = delay

        if avg_delay_details[0] == 0: # check if no delay recorded yet
                avg_delay_details[1] += 1
                avg_delay_details[0] = delay
        else:
                avg_delay_details[1] += 1
                avg_delay_details[0] += delay

        avg_delay = avg_delay_details[0] / avg_delay_details[1]

        return min_delay, avg_delay, max_delay, avg_delay_details

    def doTraceroute(self, traceroute_socket, dest_addr):
        dest_reached = False
        ttl = 0

        packets_sent = 0
        packets_lost = 0

        # setting delay variables
        min_delay = 0.0
        avg_delay_details = [0.0, 0.0] # total delay and number of delays recorded
        avg_delay = 0.0
        max_delay = 0.0

        while not dest_reached:
                packet = self.packetConstructWithChecksum()
                self.seq_number += 1

                ttl += 1 # increment ttl

                traceroute_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

                for i in range(3):
                    send_time = self.sendPing(traceroute_socket, packet, dest_addr)
                    packets_sent += 1

                    try: # if timeout occurs, -1 is returned to trigger typeerror and increase ttl without printing results
                        recv_time, recv_addr, packet_length, recv_header = self.recvPing(traceroute_socket)
                    except TypeError:
                        packets_lost += 1
                        break

                    total_delay = self.handleResults(recv_addr, send_time, recv_time, packet_length, ttl) # printing each result

                    min_delay, avg_delay, max_delay, avg_delay_details = self.calcDelays(total_delay, min_delay, max_delay, avg_delay_details)

                dest_reached = self.checkDestReached(recv_header)

        packet_loss = (packets_lost / packets_sent) * 100
        self.printAdditionalDetails(packet_loss, min_delay, avg_delay, max_delay)
        
        traceroute_socket.close()

    def __init__(self, args):
        # Please ensure you print each result using the printOneResult method!
        print('Traceroute to: %s...' % (args.hostname))

        self.own_id = os.getpid() & 0xFFFF
        self.seq_number = 1

        # looking up and resolving hostname
        try:
                ip = socket.gethostbyname(args.hostname)
        except socket.gaierror as msg:
                print("gaierror: " + str(msg))
                sys.exit(1)

        try: # handle protocol argument
            if args.protocol.upper() == "UDP":
                traceroute_socket = self.makeUDPSocket()
            else:
                traceroute_socket = self.makeICMPSocket()
        except AttributeError: # if protocol argument doesn't exist
            traceroute_socket = self.makeICMPSocket()

        #print("IP = " + ip)
        #print("-"*32)

        try:
            self.timeout = args.timeout
        except AttributeError: # if timeout argument doesn't exist
            self.timeout = 5

        self.doTraceroute(traceroute_socket, ip)
                

class WebServer(NetworkApplication):

    def handleRequest(self, tcpSocket):
        # 1. Receive request message from the client on connection socket
        req = tcpSocket.recv(1024).decode('utf-8')
        #print(req)

        # 2. Extract the path of the requested object from the message (second part of the HTTP header)
        request_list = req.split(' ') # splitting the request into parts

        req_type = request_list[0] # first part is request type, like GET
        req_file = request_list[1] # second part is requested file
        
        # 3. Read the corresponding file from disk
        file = req_file.split('?')[0] # splitting '?' data from path if included
        file = file.lstrip('/') # strip leading /
        
        if file == "" or file == " ": # check if specific page isn't given, meaning the index/homepage is wanted
            file = "index.html"
        
        try:
            open_file = open(file, 'rb') # open file to read in byte format
            response = open_file.read()
            open_file.close()

            # successful response header
            header = "HTTP/1.1 200 OK\n"

            # checking file types
            if file.endswith(".jpg"):
                mimetype = "image/jpg"
            elif file.endswith(".png"):
                mimetype = "image/png"
            elif file.endswith(".css"):
                mimetype = "text/css"
            else:
                mimetype = "text/html"

            header += "Content-Type: " + str(mimetype) + "\n\n"
        except FileNotFoundError:
            header = "HTTP/1.1 404 Not Found\n\n"
            response = "<html><body><center><h3>Error 404: File not found</h3><p>Python HTTP Server</p></center></body></html>".encode('utf-8')


        # 5. Send the correct HTTP response error
        final_response = header.encode('utf-8')
        final_response += response
        #print(final_response)

        # 6. Send the content of the file to the socket
        tcpSocket.send(final_response)

        # 7. Close the connection socket
        tcpSocket.close()

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))

        # 1. Create server socket
        server_address = ('127.0.0.1', args.port)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # 2. Bind the server socket to server address and server port
        server_socket.bind(server_address)

        # 3. Continuously listen for connections to server socket
        server_socket.listen(1)
        serving = True
        while serving:
            try:
                connection, address = server_socket.accept()
                # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
                self.handleRequest(connection)
            except socket.error as msg:
                # 5. Close server socket
                if server_socket:
                    server_socket.close()
                print(msg)
                sys.exit(1)


class Proxy(NetworkApplication):

    def handleRequest(self, tcp_socket):
        print("New connection accepted")
        full_req = tcp_socket.recv(1024).decode('utf-8') # receive request from client
        #print("Full req =", full_req)

        # split request according to spaces
        first_line = full_req.split('\n')[0]
        #print(first_line)

        # extract useful parts from the request
        full_url = first_line.split(' ')[1]

        # get just the url
        http_pos = full_url.find("://")
        #print("HTTP Pos =", http_pos)
        if http_pos == -1:
            temp = full_url
        else:
            temp = full_url[(http_pos+3):]

        port_pos = temp.find(":") # find the position of the port

        webserver_pos = temp.find("/") # find the end of the webserver address
        if webserver_pos == -1:
                webserver_pos = len(temp)
                
        webserver = ""
        port = -1
        if port_pos == -1 or webserver_pos < port_pos:
                port = 80
                webserver = temp[:webserver_pos]
        else: # port has been specified
                port = int((temp[(port_pos+1):])[:webserver_pos-port_pos-1])
                webserver = temp[:port_pos]
            
        #print("temp =", temp)
        #print("webserver =", webserver, "port =", port)

        # see if domain can be converted to ip. If not, use the domain name as last resort
        try:
            ip = socket.gethostbyname(webserver)
        except socket.gaierror as msg:
            print("Couldn't convert domain to ip")
            ip = final_url

            if tcp_socket:
                tcp_socket.close()
            sys.exit(1)
        #print("IP =", ip)

        try:
            request_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create new socket for sending request
            request_socket.settimeout(2)
            request_socket.connect((ip, port)) # connect to end server
            request_socket.send(full_req.encode('utf-8')) # send main request
            #print("forwarded the request")

            # receive data from the server
            while 1:
                #print("Looped")
                reply = request_socket.recv(1024)
                #print(reply)
                #print(len(reply))

                if len(reply) > 0:
                    # send reply back to browser
                    tcp_socket.send(reply)

                    print("Requested packet sent")
                else: # break from receiving if no more data is sent
                    print("Connection ended")
                    break
            request_socket.close()
        except socket.timeout: # if timeout occurs
            print("Connection ended")
            if request_socket:
                request_socket.close()
            return
        except socket.error as msg: # if other error occurs
            print("Socket error:", msg)
            if request_socket:
                request_socket.close()
            if tcp_socket:
                tcp_socket.close()
            sys.exit(1)
        #print("Bottom of handleRequest")

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))

        # 1. Create server socket
        server_address = ('127.0.0.1', args.port)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # 2. Bind the server socket to server address and server port
        server_socket.bind(server_address)

        # 3. Continuously listen for connections to server socket
        server_socket.listen(1)
        serving = True
        while serving:
            try:
                connection, address = server_socket.accept()
                # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
                self.handleRequest(connection)
            except socket.error as msg:
                # 5. Close server socket
                if server_socket:
                    server_socket.close()
                print("Socket error:", msg)
                sys.exit(1)


if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
