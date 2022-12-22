from scapy.all import sniff
import os
import time
import sqlite3

ips_file = os.environ["LIST_OF_IPS"].replace("\\","/")
opted_out_ips_file = os.environ["OPTED_OUT_IPS"].replace("\\","/")
database = os.environ["DATABASE_OF_IPS"].replace("\\","/")


def add_to_database(query, args):
	conn = sqlite3.connect(database)
	cursor = conn.cursor()
	cursor.execute(query, args)
	conn.commit()
	conn.close()


while True:
	try:
		# get 10 pkts at a time on the RADMIN VPN interface (ips of players playing the game are udp)
		pkts = sniff(filter="udp", count=100, iface="Radmin VPN")

		#get source ip from packet
		for pkt in pkts:
			#print(pkt.show())
			if pkt.haslayer("IP") and pkt is not None:
				ip = pkt["IP"].src
				dns = None

				#get dns info if applicable
				if pkt.haslayer("DNS") and pkt["DNS"].qr == 0: dns = pkt["DNS"].qd.qname 

				#get ips of people who opted out of being pinged
				with open(opted_out_ips_file, "r") as f:
					opted_out_ips = f.readlines()

					# Check if the target ip is in the list of ip_list
					if ip not in opted_out_ips:
						if dns:
							add_to_database("INSERT OR REPLACE INTO ipinfo(ip, dns_name) VALUES (?, ?)", (ip, dns))
							print("IP", ip, "with DNS", dns, "added.")
						else:
							add_to_database("INSERT OR REPLACE INTO ipinfo(ip, dns_name) VALUES (?, ?)", (ip, "no_dns_info"))
							print("IP", ip, "added.")

		time.sleep(10)

	except Exception as e:
		print(e)

