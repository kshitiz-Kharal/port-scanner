import nmap
import ipaddress

print('Hey user,\nThis is a python program to scan a range of ip addresses.\nYou need to have nmap and python installed in your system to run this application!\n')


# function to take ipv4 as input and validate the input
def take_ip():
    ip = input('Enter the IP address you want to scan: ')
    ip_list = ip.split('.')
    try:
        if str(type(ipaddress.ip_address(ip)))=="<class 'ipaddress.IPv4Address'>":
            print('working')
            return ip
    except ValueError:
        print('Please enter a valid ip address')
        take_ip()
    return ip
    
    
# function to input range of ipv4 addresses to scan and validate them
def take_range():
    print('Enter the range of ports separated by "-", for example <port>-<port>:<1>:<90>')
    print('Port range should be <minimum>-<maximum>')
    port_range= input('Enter the range of port you want to scan: ')
    port_range_listed = port_range.split('-')
    
    
    # validating input if ports can be converted into integer or not
    for i in port_range_listed:
        try:
            int(i)
            
        except ValueError:
            print('\n\nPlease enter a valid input')
            take_range()
            
    # verifying if only one port is given
    if len(port_range_listed)>1:
    	min_port=int(port_range_listed[0])
    	max_port=int(port_range_listed[1])
    	return min_port,max_port
    return int(port_range_listed[0]),int(port_range_listed[0])

    if min_port>max_port or min_port<0 or max_port>65535:
        print('Please enter a valid port range\n')
        take_range()


        
#scanner to scan the network and give output

target_host = take_ip()
min_port,max_port=take_range()
nm = nmap.PortScanner()
for ports in range(min_port,max_port+1,1):
    result = nm.scan(target_host, str(ports), "-Pn -sC -sV")
    command_used = result['nmap']['command_line']
    scan_result = result['scan'][target_host]['tcp'][ports]['state']
    reason = result['scan'][target_host]['tcp'][ports]['reason']
    version = result['scan'][target_host]['tcp'][ports]['version']
    service = result['scan'][target_host]['tcp'][ports]['name']
    
    if version == '':
    	version='Not Found'
    if ports==min_port:
	    print(f"Command used:{command_used}")
	    print("\n-_-_-_-_-_-_-_-_-_-_-_-_-_-  === === ===  RESULT  === === ===  -_-_-_-_-_-_-_-_-_-_-_-_-_- \n")
    print(f"The port {ports} is {scan_result},reason: {reason} service:{service}, version:{version}")
    
    
    



