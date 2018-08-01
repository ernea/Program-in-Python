import pyshark
import os.path
import mysql.connector
import localdb
#import concurrent.futures
print("Press '1' if you want to start new capture.\nPress '2' if you want to extract data from existing file")
selection=input()
if (selection=='1'):
	print("Enter the file name to store captured packet:")
	filename=input()
	if (os.path.isfile(filename)):
		print("File already exist. Do you want to replace the file. y/n")
		choice=input()
		if(choice=='y'):
			open(filename,'w').close()
		else:
			print("Enter filename again:")
			filename=input()
	print("Capturing.........")
	capture=pyshark.LiveCapture(interface='Ethernet 4', output_file=filename)		
#capture.set_debug(True)
	capture.sniff(packet_count=10)
	print(capture)

	
	def packet_description(pkt):
	#for pkt in capture:	
		src=pkt.ip.src
		dest=pkt.ip.dst
		length=pkt.length
		protocol=pkt.transport_layer
		print (src, dest, length, protocol)
		localdb.insert(src, dest, length, protocol)
		
	capture.apply_on_packets(packet_description)
else:
	pass
	
	

