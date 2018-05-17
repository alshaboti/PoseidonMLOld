import os
import sys
import subprocess
from collections import OrderedDict
import datetime
import json

other_proto = []

def parse_packet_head(line):
    '''
    Parses the head of the packet to get the key tuple which contains
    the flow level data

    Args:
        line: Header line from tcpdump

    Returns:
        key: Tuple key which contains packet info
    '''

    # Split the header line into its components
    data = line.decode('utf8')
    data = data.split(' ')

    # Only generate a key if this packet contains IP information
    if len(data) < 2:
        return None
    # here only IP for ipv4, IPv6 shows IP6 instead of IP
    if data[2] != 'IP':
        other_proto.append(data[2])
        return None


    # Parse out the date and time the packet was seen
    date_str = data[0] + ' ' + data[1]
    date = datetime.datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S.%f')

    # Parse out the source and destination addresses and ports
    source_data = data[3].split('.')
    if len(source_data) < 5:
        source_port = '0'
    else:
        source_port = source_data[4]

    source_str = '.'.join(source_data[0:4]) + ':' + source_port

    destination_data = data[5].split('.')
    if len(destination_data) < 5:
        destination_port = '0'
        destination_str = '.'.join(destination_data[0:4])[0:-1] \
                          + ':' \
                          + destination_port

    else:
        destination_port = destination_data[4][0:-1]
        destination_str = '.'.join(destination_data[0:4]) \
                          + ':' \
                          + destination_port

    return (date, source_str, destination_str)


def parse_packet_data(line):
    '''
    Parses the hex data from a line in the packet and returns it as a
    string of characters in 0123456789abcdef.

    Args:
        line: Hex output from tcpdump

    Returns:
        packet_data: String containing the packet data
    '''
    raw_data = line.decode('utf-8')
    try:
        _, data = raw_data.split(':', 1)
    except ValueError:
        return None
    packet_data = data.strip().replace(' ' ,'')

    return packet_data


def packetizer(path):
    '''
    Reads a pcap specified by the path and parses out the packets.
    tcpdump output will look like
 00:00:00.824825 IP 198.50.110.244.1935 > 192.168.1.166.40933: Flags [.], ack 1862544037, win 159, options [nop,nop,TS val 651520168 ecr 13167038], length 0
	0x0000:  0024 e411 18a8 14cc 2051 33ea 0800 4500
	0x0010:  0034 db79 4000 3006 77d5 c632 6ef4 c0a8
	0x0020:  01a6 078f 9fe5 f926 3d24 6f04 2aa5 8010
	0x0030:  009f 8d3b 0000 0101 080a 26d5 68a8 00c8

    Packets will be stored with a tuple key formatted as follows:
    (datetime, sIP:sPort, dIP:dPort, protocol, length)

    Args:
        path: Path to pcap to read

    Returns:
        packet_dict: Dictionary of packets with keys formatted as above
    '''

    # Read get the pcap info with tcpdump
    FNULL = open(os.devnull, 'w')
    proc = subprocess.Popen(
                            'tcpdump -nn -tttt -xx -r' + path,
                            shell=True,
                            stdout=subprocess.PIPE,
                            stderr=FNULL
                           )
    head = None
    packet_dict = OrderedDict()
    # Go through all the lines of the output
    for line in proc.stdout:
        if not line.startswith(b'\t'):
            head = parse_packet_head(line)
            if head is not None:
                packet_dict[head] = ''
        else:
            data = parse_packet_data(line)
            if head is not None and data is not None:
                packet_dict[head] += data
    return packet_dict


def sessionizer(path, duration=None, threshold_time=None):
    '''
    Reads a pcap specified by the path and parses out the sessions.
    Sessions are defined as flows with matching sourceIP:sourcePort
    and destinationIP:destinationPorts. The sessions can also be binned
    in time according to the optional duration parameter.

    Args:
        path: Path to pcap to read
        duration: Duration of session bins. None uses a single bin for
                  the entire pcap.

    Returns:
        session_dict: Dictionary of sessions with keys as tuples of
                      (sourceIP:sourcePort, destIP:destPort)
    '''

    # Get the packets from the pcap
    packet_dict = packetizer(path)    

    # Go through the packets one by one and add them to the session dict
    # each session is a working_dict with all connection and packets in that duration time
    sessions = []
    # save the begnining of the bin
    start_time = None
    # all sessions in the bin but only their packets after the threshold from the firstpacket in the file
    working_dict = None


    first_packet_time = None
    # all sessions keys with their start time,
    # used to check later if a packet belong to a session starts after the threshold
    # i.e. all session starts within the threshold are discarded.
    session_starts = OrderedDict()

    # Get threshold time from config
    if threshold_time is None:
        try:
            with open('my_config.json', 'r') as config_file:
                config = json.load(config_file)
                threshold_time = config['session threshold']
        except Exception as e:
            threshold_time = 120

    for head, packet in packet_dict.items():

        time = head[0]
        # Get the time of the first observed packet
        if first_packet_time is None:
            first_packet_time = time

        # Start off the first bin when the first packet is seen
        if start_time is None:
            start_time = time
            working_dict = OrderedDict()

        # If duration has been specified, check if a new bin should start
        # shaboti: duration determine the the session time long.
        if duration is not None:
            if (time-start_time).total_seconds() >= duration:
                # save previous session session bin and start new bin
                sessions.append(working_dict)
                # create new session
                working_dict = OrderedDict()
                start_time = time

        # Add the key to the session dict if it doesn't exist
        # key1 src to dest
        key_1 = (head[1], head[2])
        # key2 dest to src
        key_2 = (head[2], head[1])
        # both represent same session.

        # Select the appropriate ordering
        if key_2 in working_dict:
            key = key_2
        if key_1 in working_dict:
            key = key_1

        # if both are not in working_dict
        if key_1 not in working_dict and key_2 not in working_dict:
            # if both are not in the sessions that are recorded during the cutoff (threshold)
            if key_1 not in session_starts and key_2 not in session_starts:
                # add the session to the list
                session_starts[key_1] = time

            # if not get the session start time
            if key_1 in session_starts:
                session_start = session_starts[key_1]
            if key_2 in session_starts:
                session_start = session_starts[key_2]

            key = key_1
            # check if the session starts after the cutoff (threshold)
            if (session_start - first_packet_time).total_seconds() > threshold_time:
                # start to make a working dictionary to collect its packets
                working_dict[key] = []

        # Add the session to the session dict if it's start time is after
        # the cutoff (threshold_time)
        if key in working_dict:
            working_dict[key].append((head[0],packet))

    if duration is not None and working_dict is not None:
        if len(working_dict) > 0:
            for key, packets in working_dict.items():
                print(key, len(packets))
            sessions.append(working_dict)
    if duration is None:
        sessions.append(working_dict)

    return sessions
