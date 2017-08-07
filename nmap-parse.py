import xml.etree.ElementTree as ET
import os
import re
import csv
     
def parseXML(xml_root):
    #Function parses host records from XML file and return list of Host objects
    ports = []
    for host in xml_root.findall("./host"):
        #Get IPv4 address
        try:
            ip = host.find("./address[@addrtype='ipv4']").attrib['addr']
        except:
            ip = ''
      
        #Get ports
        for port in host.findall("./ports/port"):
            port_dict = {}
            port_dict['ip']= ip
            port_dict['number'] = port.attrib['portid']
            port_dict['protocol'] = port.attrib['protocol']
            port_dict['state'] = port.find('./state').attrib['state']

            if port.find('./service') is not None:
                port_dict['service'] = port.find('./service').attrib['name']
            else:
                port_dict['service'] =''
        if port_dict not in ports:
            ports.append(port_dict)
    return ports

def parseGNMAP(filename):
    #Function parses host records from GNMAP file and return list of Host objects
    print filename
    #Compile regex for further use
    re_ports = re.compile('^Host:\s.*Ports')
    re_port_ignored = re.compile('^.*Ignored.*$')
    re_port_strip = re.compile('(?<=(Ports:))(.*)$')
    re_ignored_strip = re.compile('^(.*?)(?=Ign)')
    re_IP = re.compile('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')

    ports = []
    with open(filename, 'r') as file:
        for line in file:            
            if re_ports.match(line): #Regex for "Host: 190.144.154.36 () Ports: 80/open/tcp//http-proxy//F5 BIG-IP load balancer http proxy/, 443/open/tcp//ssl|https//BigIP/    Ignored State: filtered (998)"              
                ip = re.search(re_IP, line).group()    #Find IP address of host (HOST: $IP ...)
                stripped_line = re.findall(re_port_strip, line)[0][1]  #Strip string "Host: $IP Ports: $portsinfo" to just $portinfo
                if re_port_ignored.search(stripped_line):
                    stripped_line = re.search(re_ignored_strip, stripped_line).group()    #If there is "Ignored ports" in the EOL, strip it
                for port in stripped_line.split(','): #For each $port in "$port,$port,$port"
                    port_dict = {}
                    port_dict['ip'] = ip
                    port_line = port.strip().split('/') #Get list of port fields from "$port_number/$protocol/$state..."
                    port_dict['number'] = port_line[0]
                    port_dict['protocol'] = port_line[2]
                    port_dict['state'] = port_line[1]
                    port_dict['service'] = port_line[4]
                if port_dict not in ports:
                    ports.append(port_dict)    
    return ports

def parseNmapFiles(folder):
    ports = []
    for filename in os.listdir(folder):
        if  filename.endswith('gnmap'): #Parse GNMAP files
            ports += parseGNMAP(folder + '/' + filename)
        if filename.endswith('xml'): #Parse XML files
            try:
                tree = ET.parse(folder + '/' + filename)
                print folder + '/' + filename
            except:
                print "\nThere was an error with parsing XML file: %s \n" % folder + '/' + filename
                continue
            ports += parseXML(tree.getroot())
    #Dedup and sort by IP
    results = []
    for port in ports:
        if port not in results:
            results.append(port)
    results = sorted(results, key=lambda x: (x['ip'], x['number']))
    return results

def saveToCSV(results):
    with open('parsed_results.csv', 'wb') as cvs_file:
        csv_fields = ['ip', 'number', 'protocol', 'state', 'service']
        csv_writer = csv.DictWriter(cvs_file, csv_fields, restval='None', delimiter=';')
        csv_writer.writeheader()

        for result in results:
            csv_writer.writerow(result)

def main():
    nmap_folder = './Sources'
    results = parseNmapFiles(nmap_folder)
    saveToCSV(results)
	
if __name__ == "__main__":
	main()