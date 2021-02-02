#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
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

    def buildHeader(self, checksum=0):
        # header is type (8), code (8), checksum (16), id (16), sequence_num (16)
        hdr = struct.pack("!BBHHH",
                          ICMP_ECHO_REQUEST,
                          0,
                          checksum,
                          self.own_id,
                          self.seq_number)
        return hdr

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
        #print(len(reply))
        replyHeader = struct.unpack("!BBHHH", reply[20:28]) # icmp header of the received packet, bottom of packet because of network byte-order
        replyBody = struct.unpack("!BBHHHBBHII", reply[:20]) # body of the received packet

        #print(replyHeader)
        #print(replyBody)
        
        # 5. Check that the ID matches between the request and reply
        if replyHeader[3] != self.own_id:
                print("Received packet ID does not match sent packet with sequence number " + self.seq_number)
                print("Ending program")
                sys.exit(1)
                
        # 6. Return recv time + packet size
        return (recv_time, len(reply), replyBody[5])

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        # 1. Build ICMP header

        # dummy header
        packet = self.buildHeader()
        
        # 2. Checksum ICMP packet using given function
        checksum = NetworkApplication.checksum(NetworkApplication, packet)
        
        # 3. Insert checksum into packet
        packet = self.buildHeader(checksum)
        
        # 4. Send packet using socket
        try:
            icmpSocket.sendto(packet, (destinationAddress, 1)) #port doesn't matter for icmp message
        except socket.error as msg:
            print("Error sending icmp packet to destination. Error: " + str(msg))
            sys.exit(1)
            
        # 5. Record time of sending
        send_time = time.time()
        return send_time
        
    def doOnePing(self, destinationAddress, timeout):
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
        
        # 5. Return total network delay
        total_delay = recv_details[0] - send_time
        ping_details = (total_delay, packet_len, ttl)

        return ping_details

    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))

        self.own_id = os.getpid() & 0xFFFF
        self.seq_number = 1
        
        # 1. Look up hostname, resolving it to an IP address
        try:
                ip = socket.gethostbyname(args.hostname)
        except socket.gaierror as msg:
                print("gaierror has occurred: " + str(msg))
                sys.exit(1)

        print("IP = " + ip)
        print("-"*32)
        
        # 2. Call doOnePing function, approximately every second
        while True:
                time.sleep(1)

                ping_details = self.doOnePing(ip, 5)
                
                # 3. Print out the returned delay (and other relevant details) using the printOneResult method
                self.printOneResult(ip, ping_details[1], ping_details[0], ping_details[2]) #destAddr, packLen, delayTime, ttl, destHostName(optional)
                
                # 4. Continue this process until stopped
                self.seq_number += 1


class Traceroute(NetworkApplication):

    def __init__(self, args):
        # Please ensure you print each result using the printOneResult method!
        print('Traceroute to: %s...' % (args.hostname))


class WebServer(NetworkApplication):

    def handleRequest(tcpSocket):
        # 1. Receive request message from the client on connection socket
        # 2. Extract the path of the requested object from the message (second part of the HTTP header)
        # 3. Read the corresponding file from disk
        # 4. Store in temporary buffer
        # 5. Send the correct HTTP response error
        # 6. Send the content of the file to the socket
        # 7. Close the connection socket
        pass

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        # 1. Create server socket
        # 2. Bind the server socket to server address and server port
        # 3. Continuously listen for connections to server socket
        # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
        # 5. Close server socket


class Proxy(NetworkApplication):

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))


if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
