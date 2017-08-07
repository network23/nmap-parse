import xml.etree.ElementTree as ET
import os, re, pandas


class Host:
    def __init__(self, ip, hostname='', ports=[], os='', mac='', mac_vendor='', uptime='', net_distance=''):
        self.ip = ip
        self.hostname = hostname
        self.ports = []
        self.os = os
        self.mac = mac
        self.mac_vendor = mac_vendor
        self.uptime = uptime
        self.net_distance = net_distance
    def add_port(self, port):
        self.ports.append(port)

class Port:
    def __init__(self, number, protocol, state = '' , service = '', version = '', product = '', uptime = ''):
        self.number = number
        self.protocol = protocol
        self.state = state
        self.service = service
        self.version = version  
        self.product = product
        self.uptime = uptime

dict host = {
    'ip' = '',
    'hostname' = '',
    'ports' = []
    }

dict port = {
    'number' = '',
    'protocol' = '',
    'state' = '',
    'service = '',
    'version' = '',
    'product' = ''
    }
        
def ImportNmapFromXML(xml_root):
    #Function parses host records from XML file and return list of Host objects
    file_hosts = []
    for host in xml_root.findall("./host"):
        h_hostname = '' 
        #Get IPv4 address
        h_ip = host.find("./address[@addrtype='ipv4']").attrib['addr']
        #Get hostname, if there is one
        if host.find("./hostnames/hostname") is not None:
            hostname = host.find("./hostnames/hostname").attrib['name']    
        new_host = Host(h_ip, h_hostname)
        new_host.os = host.find('./os/osmatch').attrib['name'] if host.find('./os/osmatch') is not None else ''
        new_host.uptime = host.find('./uptime').attrib['seconds'] if host.find('./uptime') is not None else ''
        #Get ports
        for port in host.findall("./ports/port"):
            p_number = port.attrib['portid']
            p_protocol = port.attrib['protocol']
            p_state = port.find('./state').attrib['state']

            if port.find('./service') is not None:
                p_service = port.find('./service').attrib['name']
                p_version = port.find('./service').attrib['version'] if 'version' in port.attrib else ''
                p_product = port.find('./service').attrib['product'] if 'product' in port.attrib else ''
            else:
                p_service =''; p_version =''; p_product=''

            new_port = Port(p_number, p_protocol, p_state, p_service, p_version, p_product)
            new_host.add_port(new_port)
        file_hosts.append(new_host)
    return file_hosts

def parseXML(xml_root):
    #Function parses host records from XML file and return list of Host objects
    hosts = []
    for host in xml_root.findall("./host"):
        host_dict = {}
        host_dict['ports'] = []
        #Get IPv4 address
        try:
            host_dict['ip'] = host.find("./address[@addrtype='ipv4']").attrib['addr']
        except:
            host_dict['ip'] = ''
        #Get hostname, if there is one
        if host.find("./hostnames/hostname") is not None:
            host_dict['hostname'] = host.find("./hostnames/hostname").attrib['name']    
        else:
            host_dict['hostname'] = ''

        #Get ports
        for port in host.findall("./ports/port"):
            port_dict = {}
            port_dict['number'] = port.attrib['portid']
            port_dict['protocol'] = port.attrib['protocol']
            port_dict['state'] = port.find('./state').attrib['state']

            if port.find('./service') is not None:
                port_dict['service'] = port.find('./service').attrib['name']
                port_dict['version'] = port.find('./service').attrib['version'] if 'version' in port.attrib else ''
                port_dict['product'] = port.find('./service').attrib['product'] if 'product' in port.attrib else ''
            else:
                port_dict['service'] =''; port_dict['version'] =''; port_dict['product']=''
            host_dict['ports'].append(port_dict)
        hosts.append(host_dict)
    return hosts

def nmapFromGNMAP(filename):
    #Function parses host records from GNMAP file and return list of Host objects
    print filename
    #Compile regex for further use
    re_ports = re.compile('^Host:\s.*Ports')
    re_port_ignored = re.compile('^.*Ignored.*$')
    re_port_strip = re.compile('(?<=(Ports:))(.*)$')
    re_ignored_strip = re.compile('^(.*?)(?=Ign)')
    IP_pattern = re.compile('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')

    file_hosts = []
    with open(filename, 'r') as file:
        for line in file:            
            if re_ports.match(line): #Regex for "Host: 190.144.154.36 () Ports: 80/open/tcp//http-proxy//F5 BIG-IP load balancer http proxy/, 443/open/tcp//ssl|https//BigIP/    Ignored State: filtered (998)"                      
                ip = re.search(IP_pattern, line).group()    #Find IP address of host (HOST: $IP ...)
                new_host = Host(ip) #Create new Host object with finded IP address
                clean_line = re.findall(re_port_strip, line)[0][1]  #Strip string "Host: $IP Ports: $portsinfo" to just $portinfo
                if re_port_ignored.search(clean_line):
                    clean_line = re.search(re_ignored_strip, clean_line).group()    #If there is "Ignored ports" in the EOL, strip it
                for port in clean_line.split(','): #For each $port in "$port,$port,$port"
                    port_line = port.strip().split('/') #Get list of port fields from "$port_number/$protocol/$state..."
                    new_port = Port(port_line[0],port_line[2],port_line[1],port_line[4],port_line[6])   #Create new Port object and populate it from parsed port fields
                    new_host.add_port(new_port) #Add port to related Host object
                file_hosts.append(new_host)
    return file_hosts

def parseNmapFiles(folder):
    hosts = []
    for filename in os.listdir(folder):
        if  filename.endswith('gnmap'): #Parse GNMAP files
            hosts += nmapFromGNMAP(folder + '/' + filename)
        if filename.endswith('xml'): #Parse XML files
            try:
                tree = ET.parse(folder + '/' + filename)
                print folder + '/' + filename
            except:
                print "\nThere was an error with parsing XML file: %s \n" % folder + '/' + filename
                continue
            hosts += ImportNmapFromXML(tree.getroot())
    return hosts

def convertToDict(hosts):
    #Pandas WriteToExcel can save list of dicts as Excel WorkSheet.
    #So we need to convert list of Host objects to list of dicts [{"IP" ip, "ports": [{"port_number": port_number, ...}]}, ...]
    result_open = []
    result_filtered = []
    result_closed = []
    results = {}    #Dict of "Open", "Filtered" and "Closed" ports lists
    for host in hosts:        
        for port in host.ports:
            host_dict = {}
            host_dict['ip'] = host.ip
            host_dict['port_number'] = port.number
            host_dict['protocol'] = port.protocol
            host_dict['state'] = port.state
            host_dict['service'] = port.service
            host_dict['product'] = port.product
            host_dict['version'] = port.version
            host_dict['hostname'] = host.hostname
            host_dict['os'] = host.os
            host_dict['mac'] = host.mac
            host_dict['mac_vendor'] = host.mac_vendor
            host_dict['net_distance'] = host.net_distance
            host_dict['uptime'] = port.uptime
            if port.state == 'open':
                result_open.append(host_dict)
            if port.state == 'filtered':
                result_filtered.append(host_dict)
            if port.state == 'closed':
                result_closed.append(host_dict)
    results["Open"] = result_open
    results["Filtered"] = result_filtered
    results["Closed"] = result_closed
    return results

def saveToExcel(results):
    result_xl = pandas.ExcelWriter('result_nmap.xls')
    result_nmap = pandas.DataFrame(results["Open"])
    result_nmap.to_excel(result_xl, "Open")
    result_nmap = pandas.DataFrame(results["Filtered"])
    result_nmap.to_excel(result_xl, "Filtered")
    result_nmap = pandas.DataFrame(results["Closed"])
    result_nmap.to_excel(result_xl, "Closed")
    result_xl.save()
	
def saveToCSV(results):
	return 0

def main():
    nmap_folder = './Sources'
    hosts = parseNmapFiles(nmap_folder)
    results = convertToDict(hosts)
    saveToExcel(results)
	
if __name__ == "__main__":
	main()
