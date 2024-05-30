#!/usr/env python
#-*- encode: utf-8 -*-

import os, platform

option_menu = '''
 [#] Recon Tools
     (1a) WHOIS Lookup
     (1b) Subdomain Enumeration (CRT)
     (1c) Port Scanner
     (1d) Directory Enumeration (Bruteforce)
 [#] Attack Tools
     (2a) HTTP GET/POST Bruteforcer
     (2b) Hash Cracker (Rainbow Tables)
     (2c) RAR/ZIP Cracker (Bruteforce)
     (2d) FTP Cracker (Bruteforce)
'''

def banner():
	print('''
                                                   .-"/   .-"/
 ▄▄▄▄·  ▄▄▄·  ▐ ▄  ▄▄ •       ▄▄▄                 /  (.-./  (
 ▐█ ▀█▪▐█ ▀█ •█▌▐█▐█ ▀ ▪▪     ▀▄ █·              /           \      .^.
 ▐█▀▀█▄▄█▀▀█ ▐█▐▐▌▄█ ▀█▄ ▄█▀▄ ▐▀▀▄              |  -=- -=-    |    (_|_)
 ██▄▪▐█▐█ ▪▐▌██▐█▌▐█▄▪▐█▐█▌.▐▌▐█•█▌              \   /       /      // 
 ·▀▀▀▀  ▀  ▀ ▀▀ █▪·▀▀▀▀  ▀█▄▀▪.▀  ▀               \  .=.    /       \\
 Capstone Project - The Bangor Squad         ___.__`..;._.-'---...  //
 Class B - Cyber Security               __.--"        `;'     __   `-.  
                              -===-.--""      __.,              ""-.  ".
                               '=_    __.---"   | `__    __'   / .'  .'
                               `'-""""           \             .'  .'
                                                  |  __ __    /   |
 [#] Recon Tools                                  |  __ __   //`'`'
     (1a) WHOIS Lookup                            |         ' | //
     (1b) Subdomain Enumeration (CRT)             |    .      |//
     (1c) Port Scanner                           .'`., , ,,,.`'.
     (1d) Directory Enumeration (Bruteforce)    .'`',.',`.` ,.'.`
 [#] Attack Tools                                ',',,,,.'...',,'
     (2a) HTTP GET/POST Bruteforcer              '..,',`'.`,`,.',
     (2b) MD5 Hash Cracker (Rainbow Tables)     ,''.,'.,;',.'.`.'
     (2c) ZIP Cracker (Bruteforce)              '.`.',`,;',',;,.;
     (2d) FTP Cracker (Bruteforce)               ',`'.`';',',`',.
 [0] Exit                                         |     |     |
                                                  (     (     |
''')

def clrscr():
	if platform.system() == 'Windows':
		os.system('cls')
	else:
		os.system('clear')