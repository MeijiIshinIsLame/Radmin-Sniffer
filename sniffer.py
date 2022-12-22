from scapy.all import sniff, PcapWriter
import os
import time

ips_file = os.environ["LIST_OF_IPS"].replace("\\","/")
opted_out_ips_file = os.environ["OPTED_OUT_IPS"].replace("\\","/")

while True:
	try:
		# get 10 pkts at a time on the RADMIN VPN interface (ips of players playing the game are udp)
		pkts = sniff(filter="udp", count=100, iface="Radmin VPN")

		#get source ip from packet
		for pkt in pkts:
			print(pkt.show())
			if pkt.haslayer("IP") and pkt is not None:
				ip = pkt["IP"].src

				#get ips of people who opted out of being pinged
				with open(opted_out_ips_file, "r") as f:
					opted_out_ips = f.readlines()

					# Open the text file in read mode
					with open(ips_file, "r") as f:
						ip_list = [line.rstrip() for line in f]

					#Scrub list of the ips of people who opted out of being pinged
					for opted_out_ip in opted_out_ips:
						if opted_out_ip in ip_list:
							ip_list.remove(opted_out_ip)
							print("removed", opted_out_ip)

					# Check if the target ip is in the list of ip_list
					if ip not in ip_list and ip not in opted_out_ips:
					    # If the ip is not present, append it to the list of ip_list
						ip_list.append(ip)
						print("IP", ip, "added.")

					# Open the text file in write mode
					with open(ips_file, "w") as f:
					    # Write the list of ip_list back to the file
					    #add line break per item as well
						ip_text = [x + "\n" for x in ip_list]
						f.writelines(ip_text)

		time.sleep(10)

	except Exception as e:
		print(e)

			#my_pcap = PcapWriter('capture.pcap')
			#my_pcap.write(pkts)
			#my_pcap.close()