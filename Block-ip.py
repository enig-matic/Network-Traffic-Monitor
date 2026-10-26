import os 
import sys
import time
from scapy.all import sniff,IP
from collections import defaultdict
import pyfiglet

name = "JANGOTRA"

ban = pyfiglet.figlet_format(
    name,
    font="slant"
)

print("\033[96m" + ban + "\033[0m")
print("=" * 60)
print('       This Script set the Threshold Frequency by Input')
print('       If we have receive packet, which packet rate is ')
print('       greater than Threshold,then block the ip')
print("=" * 60)
print("Date : 27/10/2026\n")

# Enter the frequency which you want if greater than by a particular ip then block the ip 
threshold = int(input("Enter the Threshold Frequency :"))
print(f"Threshold: {threshold}")

def packet_callback(packet):

     # we take the ip from the packet and store to the src_ip 
     src_ip = packet[IP].src

     # Add packet one by one of a particular IP
     packet_count[src_ip] += 1

     # we store current time that it receive on my device  
     current_time = time.time() 

     # we calculate the time that we want to how much packet that come to my device that is in particular seconds or minutes maye be in miliseconds
     time_interval = current_time - start_time[0]

     # if packet time interval is greate than 1, then execute the if condition
     if time_interval >= 1 :

         # we use items() because we store packet is packet count 
         #  ip means Host i.e. keys --- count means values which is whole packet  
         for ip,count in packet_count.items():

             # we calculate packet_rate because before we set threshold frequency
             # this statement tell the frequency of particular ip
             packet_rate = count / time_interval

             # this statement show if packet_rate > threshold but that ip is not add in block_ip then add it
             if packet_rate > threshold and ip not in block_ip:

                 print(f"Blocking IP: {ip}, Packet Rate: {packet_rate}")

                 #we tell the os to store ip in iptables and block ip that packet_rate is greater than threshold and drop all the packets
                 os.system(f"iptables -A INPUT -s {ip} -j DROP")

                 # after block the ip we store that ip in block_ip variable
                 block_ip.add(ip)

        # this statement write because if 1 IP is block clear all the packet from that ip , we use for another ip 's
         packet_count.clear()

         # remove the previous time and store the current time 
         start_time[0] = current_time


if __name__ == "__main__":

    # this statement (os.geteuid = 1000) if it run in root priviledge otherwise it have 0 value 
    if os.geteuid() != 0:
        print("This script require root priviledge.")
        # we use 1 because if our script don't run in root priviledge then exit the program
        sys.exit(1)

    # we have receive number of packet and count one by one using packet_count variable to store in dictionary
    packet_count = defaultdict(int)

    # we store the packet time that generate in list because we monitor multiple ip addresses 
    start_time = [time.time()]

    # we use threshold frequency of packet if is higher then block ip and add to this variable
    # we use set because set store unique value
    block_ip = set()

    print("Monitoring Network Traffic...")

    # we use filter = 'ip' because we capture ip packet with the help of sniff built in function
    # we use packet_callback instead of packet_callback() because we not send one by one packet like it send continously 
    sniff(filter='ip',prn=packet_callback)

    