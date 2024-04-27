import nmap
scanner = nmap.PortScanner()

print('Hello Everyone')
print('<--------------------------------------------------------->')

ip_addr = input('Please enter the IP address you want to scan:')
print(f"The IP you entered is {ip_addr}")
# type(ip_addr)

type_ofScan = input("""\n Enter the type of scan you want to run 
                     1)SYN ACK scan
                     2)UDP scan
                     3)Comprehensive scan\n""")
print(f"You have selected the option : {type_ofScan}")

if type_ofScan == '1':
    print('Nmap version is :',scanner.nmap_version())
    scanner.scan(ip_addr,'1-1024','-v -sS')
    print(scanner.scaninfo())
    print('IP status: ',scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print('Open ports: ',scanner[ip_addr]['tcp'].keys())
elif type_ofScan == '2':
    print('Nmap version is :', scanner.nmap_version())
    scanner.scan(ip_addr, '1-2048', '-v -sU')
    print(scanner.scaninfo())
    print('IP status: ', scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    if 'udp' in scanner[ip_addr]:
        print('Open UDP ports: ', scanner[ip_addr]['udp'].keys())
    else:
        print('No UDP ports found open.')
elif type_ofScan == '3':
    print('Nmap version is :', scanner.nmap_version())
    scanner.scan(ip_addr, '1-2048', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print('IP status: ', scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print('Open UDP ports: ', scanner[ip_addr]['tcp'].keys())
elif type_ofScan >= '4':
    print("Please enter the valid option")




