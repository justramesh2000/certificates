#!/usr/bin/python3
import socket
import requests
import datetime
#from datetime import datetime

Haproxy_Servers = ("127.0.0.1", 9999)
Log_File_Path = "log.txt"
Input_File_Path = "input.txt"
Vault_Token = "s.H8B4LbgCnGkR3BKEkAL2688l"
Vault_Base_Url = "http://localhost:8200/v1/secret/"
Haproxy_Folder_Path = "/home/ubuntu/Ramesh/haproxy/certs/"


def read_input_file(path, option):
    try:
        with open(path, 'r') as file:
            if(option == "LINE"):
                data = file.readlines()
            else:
                data = file.read()
    except Exception as e:
        write_to_file(Log_File_Path,"read_input_file : " + datetime.datetime.now()+" : " + str(e), "SINGLE")
    return data


def write_to_file(path, data, option):
    #print("writing to file "+path)
    try:
        with open(path, 'a') as file:
            if(option == "SINGLE"):
                file.write(data + '\n')
            else:
                file.write('\n'.join(data))
                file.write('\n')
    except Exception as e:
        print("write_to_file : "+ str(e))


def send_haproxy_command(haproxy_server, command):
    haproxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    haproxy_sock.settimeout(10)
    try:
        haproxy_sock.connect(haproxy_server)
        haproxy_sock.sendall(command.encode('utf-8'))
        retval = ""
        haproxy_sock.close()
    except Exception as e:
        write_to_file(Log_File_Path,"send_haproxy_command : " + datetime.datetime.now()+" : " + str(e), "SINGLE")
    finally:
        haproxy_sock.close()
    return retval




def insert_into_ha(certname, certdata):
    fullpath = Haproxy_Folder_Path + certname
    send_haproxy_command(Haproxy_Servers, "new ssl cert " + fullpath + "\n")
    strdata = read_input_file(fullpath,"Multi")
    send_haproxy_command(Haproxy_Servers, "set ssl cert " +fullpath + " <<\n%s\n" % (strdata))
    send_haproxy_command(Haproxy_Servers, "commit ssl cert " + fullpath + "\n")
    send_haproxy_command(Haproxy_Servers, "add ssl crt-list " + Haproxy_Folder_Path +" " +  fullpath + "\n")
    


def get_from_vault(url):
    try:
        # todo : read from environment variable
        vault_header = {'X-Vault-Token': Vault_Token}
        response = requests.get(url, headers=vault_header)
        from pprint import pprint
        
        data = response.json()
        
        return data
    except Exception as e:
        print(e)
        write_to_file(Log_File_Path, "get_from_vault : " + datetime.datetime.now()+" : " + str(e), "SINGLE")
    return ""


def process():
    currentcerts = read_input_file(Input_File_Path, "LINE")
    
    while True:
        differentialcerts = []
        responsefromvault = get_from_vault(Vault_Base_Url + "metadata/?list=true")
        if(responsefromvault is not None):
            try:
                certlistfromvault = responsefromvault['data']['keys']
                for key in certlistfromvault:
                    if(key not in currentcerts):
                        differentialcerts.append(key)
            except Exception as e:
                #write_to_file(Log_File_Path, " : " + str(e), "SINGLE")
                continue
        else:
            write_to_file(Log_File_Path,"process : " + datetime.datetime.now()+" : " + "vault api did not return valid response for list query", "SINGLE")
            continue

        for certkey in differentialcerts:
            certresponsefromvault = get_from_vault(Vault_Base_Url + "data/" + certkey)
            if(certresponsefromvault is not None):
                try:
                    certdata = certresponsefromvault['data']['data'][certkey]
                    
                    write_to_file(Haproxy_Folder_Path +certkey, certdata, "SINGLE")
                    insert_into_ha(certkey, certdata)
                except Exception as e:
                    #write_to_file(Log_File_Path," : " + str(e), "SINGLE")
                    continue
                currentcerts.append(certkey)
            else:
                write_to_file(Log_File_Path,"process : " + datetime.datetime.now()+" : " + "vault api did not return valid response for certificate", "SINGLE")
                continue
        if(len(differentialcerts) > 0):
            write_to_file(Input_File_Path, differentialcerts, "Multi")
process()

