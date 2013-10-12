#!/bin/python2
import pcap
import socket
import time
import struct
import sys

def ta(d):
    s = "0x%0.2X" % ord(d)
    #return hex(ord(d))
    return s

def ta_ord(d):
    s = "0x%0.2X" % d
    return s

def ta_ord4(d):
    s = "0x%0.4X" % d
    return s

def ta_ord6(d):
    s = "0x%0.6X" % d
    return s

def print16(data):
    row = 0
    column = 0
    print "%0.4X  " % (row*16),
    for d in data:
        sys.stdout.write(ta(d))
        column = column + 1
        if (column == 16):
            print ""
            row = row + 1
            column = 0
            print "%0.4X  " % (row*16),
        elif (column == 8):
            print "   ",
        else:
            print " ",

def stripJuniperEthernet(data):
    
    magic_number = (ord(data[0]) << 16) + (ord(data[1]) << 8) + ord(data[2])
    ##print ta_ord6(magic_number)
    if magic_number == 0x4d4743:
        ##print "Found Juniper Ethernet"
        ##print16(data)
        ##print ""
        extension_length = (ord(data[4]) << 8) + (ord(data[5]))
        ##print "With extension length of %s bytes" % extension_length
        header_size = 5 + extension_length
        ##print "Header size = %s" % header_size
        ##print ta_ord(ord(data[header_size+1]))
        ##print16(data[:header_size+1])
        ##print ""
        return data[header_size+1:]

    return data

class Counter:
    c = 1
    total_packets = 0
    total_rtp = 0
    total_udp = 0
    streams = {}
    streams_next_counter = {}
    streams_missing_packets = {}
    streams_out_of_order = {}
    def dump_streams(self):
        print "Processed %s packets" % self.total_packets
        print "Processed %s RTP packets" % self.total_rtp
        print "Processed %s UDP packets" % self.total_udp
        for k in self.streams.keys():
            print "%s -> %s" % (k, self.streams[k])
            print "   Missing Count: %s" % len(self.streams_missing_packets[k])
            print "   Out of Order Count: %s" % len(self.streams_out_of_order[k])

    def count(self, pktlen, data, timestamp):
        if not data:
            return

        self.total_packets += 1
        data = stripJuniperEthernet(data)
        streams = self.streams
        streams_next_counter = self.streams_next_counter
        streams_missing_packets = self.streams_missing_packets
        streams_out_of_order = self.streams_out_of_order
        """
        if (self.c == 2147):
            print "Frame: %s" % self.c
            print "Length: %s" % pktlen
            print16(data)
            print "Counter = %s" % (ta(data[57]))
            print "Type = %s" % (ta(data[58]))
        """
        rtp_version = None
        protocol = None
        if (data and len(data) >=43):
            ## RTP Version is the first 2 bits of the 55th octet
            rtp_version = ord(data[42]) >> 6
            ## 33 Octed has the IP protocol ... 17 is UDP
            protocol = ord(data[23])

            if (protocol == 17 and rtp_version == 2):
                self.total_rtp += 1
            if (protocol == 17):
                self.total_udp += 1

        """
        if (self.total_packets == 2431):
           print16(data)
           print
           print "RTP Version %s (%s)" % (rtp_version, ta_ord(ord(data[42])))
           print "Protocol %s (%s)" % (protocol, ta_ord(ord(data[23])))
           print "Packet # %s" % self.total_packets
        """
       
        if (rtp_version == 2 and protocol == 17):

            ## Get the source and destination information
            source_address = pcap.ntoa(struct.unpack('i',data[26:30])[0])
            destination_address = pcap.ntoa(struct.unpack('i',data[30:34])[0])
            source_port = (ord(data[34]) << 8) + ord(data[35])
            dest_port = (ord(data[36]) << 8) + ord(data[37])

            ## Payload is the last 7 bits in the 56th octet
            payload = ta_ord(ord(data[43]) & 0x7F)
            int_payload = ord(data[43]) & 0x7F

            ## Counter is a 16 bit field in the 57th and 58th octets
            counter = ta_ord4((ord(data[44]) << 8) + ord(data[45]))
            int_counter = (ord(data[44]) << 8) + ord(data[45])

            ## The RFC defines 96 to 127 as the dynamic payload types
            ## and this seems to be where Polycom puts the audio and video
            ## streams. We are only interested in these two streams for 
            ## this analyzer
            if (int_payload <= 127 and int_payload >= 96):

                stream_id = "%s-%s-%s" % (destination_address, dest_port, payload)

                """
                if (stream_id == "192.168.105.27-49366-0x76"):
                    print16(data)
                    print 
                    print "RTP Version %s (%s)" % (rtp_version, ta_ord(ord(data[45])))
                    print "Protocol %s (%s)" % (protocol, ta_ord(ord(data[23])))
                    print "Counter: %s, Int Counter: %s" % (counter, int_counter)
                    print "Packet # %s" % self.total_packets
                    sys.exit()
                """

                if streams.has_key(stream_id):
                    ## Alright, we are already tracking this stream
                    streams[stream_id] += 1
                    
                    if streams_next_counter[stream_id] != int_counter:
                        ## Not what we were expecting, so we have a missing packet

                        ## So, is it something we should have seen earlier
                        if streams_missing_packets[stream_id].has_key(streams_next_counter[stream_id]):
                            ## Yup, it just arrived late
                            streams_out_of_order[stream_id].append(int_counter)
                        else:
                            ## add it and everything in between to the missing packets
                            for i in range(streams_next_counter[stream_id], int_counter):
                                streams_missing_packets[stream_id][i] = 1
                    
                    ## Set the next expected sequence number
                    streams_next_counter[stream_id] = int_counter + 1

                else:
                    ## This is a new stream
                    streams[stream_id] = 1
                    ## Set the next expected counter
                    streams_next_counter[stream_id] = int_counter + 1
                    ## Initialize missing packet and out of order packet dictionaries
                    streams_missing_packets[stream_id] = {}
                    streams_out_of_order[stream_id] = []


                ##print "Protocal: %s RTP Version: %s" % (protocol, rtp_version)
                ##print "%s: %s:%s -> %s:%s" % (self.c, source_address, source_port, destination_address, dest_port),
                ##print "Counter: %s Payload: %s" % (counter, payload)


counter = Counter()

protocols={socket.IPPROTO_UDP:'udp'}

p = pcap.pcapObject()

#filename = "./samples/490_to_houston_135mpls_packet_loss_50_percent--at135wan/pcap"
filename = "./samples/490_to_phoenix/pcap_490_to_phoenix_135wan--at_490"
p.open_offline(filename)


## Read the whole file
#p.loop(0, counter.count)
p.loop(0, counter.count)

## dump our streams
counter.dump_streams()
