from scapy.all import sniff, PcapWriter
import os

while True:
	try:
		# get 50 pkts at a time on the RADMIN VPN interface (ips of players playing the game are udp)
		pkts = sniff(filter="udp", count=10, iface="Radmin VPN")

		#get source ip from packet with line break
		for pkt in pkts:
			ip = pkt["IP"].src

		#get ips of people who opted out of being pinged
		with open("opted_out_ips.txt", "r") as f:
			opted_out_ips = f.readlines()

			# Open the text file in read mode
			with open("ips.txt", "r") as f:
				ip_list = f.readlines()

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
			with open("ips.txt", "w") as f:
			    # Write the list of ip_list back to the file
			    #add line break per item as well
				f.writelines([ip_list + "\n" for line in ip_list])

	except Exception as e:
		print(e)

			#my_pcap = PcapWriter('capture.pcap')
			#my_pcap.write(pkts)
			#my_pcap.close()