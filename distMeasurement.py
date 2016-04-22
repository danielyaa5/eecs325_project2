import socket
import struct
import time
import sys
import string
import random
import select
import geoip2.database
from math import radians, cos, sin, asin, sqrt
import urllib

DATA_LENGTH = 1458

LOCATION_LONG = -81.6089870
LOCATION_LAT = 41.5091260

def main():
    geo_reader = geoip2.database.Reader('./GeoLite2-City.mmdb')

    input_file_name = "targets.txt" 
    output_file_name = "results.txt"

    with open(input_file_name) as f:
        websites = f.readlines()

    output_file = open(output_file_name, "w")

    print "Websites: " + str(websites)

    for website in websites:

        print ""
        print website.replace("\n", "")
        curr_website = website.replace("\n", "")
        curr_try = 0
        max_tries = 3
        SUCCESS = False 
        try:
            dest_addr = socket.gethostbyname(curr_website)
        except:
            continue

        distance = getXmlDistance(dest_addr)
        if distance == None: 
            distance = getDbDistance(geo_reader, dest_addr)

        print "Distance from destination = " + str(distance) + "km"
        print "Destination address: " + dest_addr
        port = 33434
        max_hops = 32
        default_ttl = 32
        icmp = socket.getprotobyname('icmp')
        udp = socket.getprotobyname('udp')
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)

        timeout = struct.pack("ll", 5, 0)
        recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)
        
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, default_ttl)
        recv_socket.bind(("", port))

        payload = randbytestring()

        start_time=time.time()
        send_socket.sendto(payload, (curr_website, port))

        curr_addr = None
        curr_name = None

        to = 5
        recv_socket_fd, _, _ = select.select([recv_socket], [], [], to)
        hops = 0
        rtt = 0

        while not SUCCESS and curr_try < max_tries and recv_socket_fd:
            print "curr try = " + str(curr_try)
            try:
                packet, curr_addr = recv_socket.recvfrom(2048)
                curr_addr = curr_addr[0]
                end_time = time.time()
                rtt = (end_time - start_time) * 1000
                # unpack ICMP header to get port type and code information
                icmp_header_packed = packet[20:28]
                icmp_header = struct.unpack(
                    'bbHHh', icmp_header_packed)
                icmp_type = icmp_header[0]
                icmp_code = icmp_header[1]

                print "all of ICMP header: " + str(icmp_header)

                udp_header_packed = packet[48:56]
                udp_header = struct.unpack("!HHHH",udp_header_packed)
                udp_source_port = udp_header[0]
                udp_dest_port = udp_header[1]
                udp_length = udp_header[2]

                print "all UDP header: " + str(udp_header)
                print "UDP header source port: " + str(udp_source_port)
                print "UDP header dest port: " + str(udp_dest_port)
                print "UDP header length: " + str(udp_length)

                ip_header_packed = packet[28:48]
                ip_header = struct.unpack('!BBHHHBBH4s4s', ip_header_packed)

                print "all IP header " + str(ip_header)

                ip_source_address = socket.inet_ntoa(ip_header[8])
                ip_dest_address = socket.inet_ntoa(ip_header[9])

                print "IP header source: " + ip_source_address
                print "IP header destination address: " + ip_dest_address

                if ip_dest_address == dest_addr and udp_dest_port == port and int(icmp_type == 3) and int(icmp_code == 3):
                    curr_ttl = ip_header[5] 
                    hops = default_ttl - curr_ttl
                    data_returned = len(packet[56:])
                    print "Size of data returned in ICMP error message = " + str(data_returned)
                    SUCCESS = True
                try:
                    curr_name = socket.gethostbyaddr(curr_addr)[0]
                except socket.error:
                    curr_name = curr_addr
            except socket.error:
                pass
            curr_try+=1;

            if curr_addr is not None:
                curr_host = "%s (%s)" % (curr_name, curr_addr)
            else:
                curr_host = "*"

        send_socket.close()
        recv_socket.close()

        if rtt == 0 or hops == 0:
            print "Host not reachable\n"
            output_file.write("Host not reachable\n")
        else :
            print("%s; rtt %d ms; %d hops\n" %(curr_addr, rtt, hops))
            output_file.write("name: " + curr_website + ", ip: " + curr_addr + ", rtt = " + str(rtt) + " ms, hops = " + str(hops))
            if not distance == None:
                print "the distance is " + str(distance)
                output_file.write(", distance: " + str(distance))
            output_file.write("\n")

    output_file.close()

# returns a random "bytes" object of given length 
def randbytestring(): 
    return ''.join(random.choice(string.ascii_uppercase) for i in range(DATA_LENGTH)).encode('ascii')

def getDbDistance(reader, ip):
    response = reader.city(ip)
    longitude = response.location.longitude
    latitude = response.location.latitude
    # print "longitude: " + str(longitude) + " latitude " + str(latitude)
    return haversine(longitude, latitude, LOCATION_LONG, LOCATION_LAT)

def haversine(lon1, lat1, lon2, lat2):
    """
    Calculate the great circle distance between two points 
    on the earth (specified in decimal degrees)
    """
    # convert decimal degrees to radians 
    lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])
    # haversine formula 
    dlon = lon2 - lon1 
    dlat = lat2 - lat1 
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a)) 
    km = 6367 * c
    return km


def getXmlDistance(ip):
    latitude = 0.0
    longitude = 0.0
    try:
        request = urllib.urlopen("http://freegeoip.net/xml/" + ip)
    except:
        return None
    for line in request:
        if "<Latitude>" in line:
            lat = float(line.replace("<Latitude>", "").replace("</Latitude>", ""))
        elif "<Longitude>" in line:
            lon = float(line.replace("<Longitude>", "").replace("</Longitude>", ""))
    print "longitude: " + str(longitude) + " latitude " + str(latitude)
    if latitude == 0.0 or longitude == 0.0:
        return None
    return haversine(lat, lon, LOCATION_LONG, LOCATION_LAT)

if __name__ == "__main__":
    main()
