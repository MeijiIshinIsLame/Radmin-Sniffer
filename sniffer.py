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

def get_from_database(query, args):
	conn = sqlite3.connect(database)
	cursor = conn.cursor()
	cursor.execute(query, args)
	results = cursor.fetchall()
	conn.commit()
	conn.close()
	return results

def ip_in_database_already(ip_address):
	result = get_from_database("SELECT * FROM ipinfo WHERE ip=?",(ip_address,))
	return True if result else False

while True:
	try:
		# get 100 pkts at a time on the RADMIN VPN interface (ips of players playing the game are udp)
		pkts = sniff(count=100, iface="Radmin VPN")

		#get source ip from packet
		for pkt in pkts:
			#print(pkt.show())
			if pkt.haslayer("IP") and pkt is not None:
				ip = pkt["IP"].src
				dns = None

				#get dns info if applicable
				if pkt.haslayer("DNS") and pkt["DNS"].an: 
					dns = pkt["DNS"].an.rdata.decode("utf-8").split("::")[0]

				#get ips of people who opted out of being pinged
				opted_out_ips = ""
				with open(opted_out_ips_file, "r") as f:
					opted_out_ips = f.readlines()

				# Check if the target ip is in the list of ip_list
				if ip not in opted_out_ips:
					#If theres a DNS entry we want to update the old one
					if dns:
						add_to_database("INSERT OR REPLACE INTO ipinfo(ip, dns_name) VALUES (?, ?)", (ip, dns))
						print("IP", ip, "with DNS", dns, "added.")
					else:
						add_to_database("INSERT INTO ipinfo(ip, dns_name) VALUES (?, ?)", (ip, "no_dns_info"))
						print("IP entry", ip, "added with no dns info")

		time.sleep(10)

	except Exception as e:
		print(e)

