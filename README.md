# log4j-scanner
A Log4j vulnerability scanner is automated scanner to find log4j (CVE-2021-44228 and CVE_2021_45046) vulnerabilities in web applications.


#Features
1- It supports multiple URL to perform scan
2- It has payload that can bypass some WAF
3- It supports GET and POST request
4- It supports user payload and headers file
5- It fuzzes POST data parameter as well as JSON parameter

#Installing 

git clone https://github.com/google/log4jscanner.git
cd log4j-scanner
./log4jscan.py -h

#USAGE

Usage : ./log4jscan.py [options- URL/list_of_URL] [target_specification ] [options-custom_dns_callback_host] [id_of_custom_dns_callback_host]

optional arguments:
  -h, --help            show this help message and exit
  
  -u URL, --url URL     Scan a single URL
  
  -l LIST, --list LIST  Scan multiple URL from file
  
  -id CALLBACK_HOST, --custom_dns_callback_host CALLBACK_HOST
                        Custom dns callback provider ID
                         
  --test_cve_2021_45046   Test with CVE 2021 45046 Payloads only. Using this option will not test with custom Payload  [Deafult: False]
                        
  -hf HEADER_FILE, --header_file HEADER_FILE  Path for Header file to fuzz [ Default : header.txt]
                        
  --request_type REQUEST GET or POST type request [Default: GET]
                        
  --run_all_test        Run all possible test for LOG4j(all payloads , all requests) [Default: False]
  
  --include_wafbypass_payload To include firewall bypass payloads [Default: False]
                        
  --custom_payload_list CUSTOM_PAYLOAD Path for custom payload file.
                        

Example : ./log4jscan.py -u http://127.0.0.1:8080/ -id c9d9k5c2vtc00002me60grsw31ayyyyyb.interact.sh

#Scanning single url

./log4jscan.py -u http://127.0.0.1:8080 -id c9d9k5c2vtc00002me60grsw31ayyyyyb.interact.sh

#Scanning mulitple URL

./log4jscan.py -l URLS.txt -id c9d9k5c2vtc00002me60grsw31ayyyyyb.interact.sh


