# -*- coding: utf-8 -*-
import os, sys
import yaml
import subprocess
import json
import pathlib
from multiprocessing import Pool
import re
import time
from netaddr import *
import geoip2.database
import ssdeep
from hdfs import InsecureClient

class pcap_parser:
    def __init__ (self, pcap):
        self.pcap = pcap
        self.pcap_json = list()
        self.city_reader = geoip2.database.Reader('/home/antslab/GeoIP2-DB/GeoIP2-City_20200526/GeoIP2-City.mmdb')
        self.domain_reader = geoip2.database.Reader('/home/antslab/GeoIP2-DB/GeoIP2-Domain_20200526/GeoIP2-Domain.mmdb')
        self.isp_reader = geoip2.database.Reader('/home/antslab/GeoIP2-DB/GeoIP2-ISP_20200526/GeoIP2-ISP.mmdb')
        self.city_reader_response = dict()
        self.domain_reader_response = dict()
        self.isp_reader_response = dict()
        try:
            with open(os.path.join('src','settings.yml'), 'r', encoding='utf-8') as v:
                self.yaml = yaml.safe_load(v)
        except:
            return None

    def proc(self):
        self.parse()
        for record in self.json:
            # 將packet中的payload convert to ssdeep hash value
            try:
                record['_source']['layers']['tcp.payload'][0] = ssdeep.hash(record['_source']['layers']['tcp.payload'][0])
                record['_source']['layers']['tcp.payload'].append(record['_source']['layers']['frame.time_epoch'][0])
                record['_source']['layers']['tcp.payload'].append(record['_source']['layers']['tcp.len'][0])
            except:
                pass
            try:
                if self.IOfilter(record['_source']['layers']['ip.dst'][0]): # ip.src is external
                    record['_source']['layers']['isInternal'] = False
                    # get external ip geoinfo(ip.src)
                    record = self.getGeoInfo(record, record['_source']['layers']['ip.src'][0], self.city_reader, self.domain_reader, self.city_reader_response, self.domain_reader_response)
                    self.pcap_json.append(record)
                else: # ip.src is internal
                    record['_source']['layers']['isInternal'] = True
                    # get external ip geoinfo(ip.dst)
                    record = self.getGeoInfo(record, record['_source']['layers']['ip.dst'][0], self.city_reader, self.domain_reader, self.city_reader_response, self.domain_reader_response)
                    self.pcap_json.append(record)
            except:
                pass
        return self.pcap_json
        
    def parse(self):
        cmd = ["tshark","-r",self.pcap, "-T", "json", "-e", "frame.time_epoch", "-e","frame.number","-e","frame.time","-e","frame.protocols","-e","ip.src","-e","ip.dst","-e","ip.proto","-e","tcp.srcport","-e","tcp.dstport","-e","frame.len","-e", "udp.length", "-e","tcp.len", "-e", "tcp.hdr_len", "-e", "udp.srcport", "-e", "udp.dstport", "-e", "icmp.length", "-e", "icmp.length.original_datagram", "-e", "tcp.payload"]
        p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stdin = subprocess.PIPE)
        (output, err) = p.communicate()
        self.json = json.loads(output)
    
    def IOfilter(self, ip):
        isInbound = False
        for netrange in self.yaml['Trap']:
            if IPAddress(ip) in IPNetwork(netrange):
                isInbound = True
                break
        return isInbound
    
    def getGeoInfo(self, record, ip, city_reader, domain_reader, city_reader_response, domain_reader_response):
        # city_info
        if ip in city_reader_response:
            try:
                record['_source']['layers']['country'] = city_reader_response[ip].country.name
            except:
                record['_source']['layers']['country'] = None
            try:
                # domain_info
                record['_source']['layers']['domain'] = domain_reader_response[ip].domain
            except:
                record['_source']['layers']['domain'] = None
            try:
                # isp_info
                record['_source']['layers']['isp'] = isp_reader_response[ip].isp
            except:
                record['_source']['layers']['isp'] = None
        else:
            try:
                city_response = city_reader.city(ip)
                self.city_reader_response[ip] = city_response
                record['_source']['layers']['country'] = city_response.country.name
            except: # AddressNotFoundError & ValueError
                record['_source']['layers']['country'] = None
            # domain_info
            try:
                domain_response = domain_reader.domain(ip)
                self.domain_reader_response[ip] = domain_response
                record['_source']['layers']['domain'] = domain_response.domain
            except:
                record['_source']['layers']['domain'] = None
            
            # isp_info
            try:
                isp_response = isp_reader.isp(ip)
                self.isp_reader_response[ip] = isp_response
                record['_source']['layers']['isp'] = isp_response.isp
            except:
                record['_source']['layers']['isp'] = None
                
        return record

def write2local(pcap, timestamp, pcap_json):
    folder = pcap[:pcap.rfind('.')]
    pathlib.Path(folder).mkdir(parents=True, exist_ok=True)
    with open(os.path.join(folder, timestamp +'.json'), 'w') as f:
        json.dump(pcap_json, f)

def write2HDFS(folder, timestamp, pcap_json):
    client_hdfs = InsecureClient('http://192.168.50.123:9870', user='hdfs')
    output_path = os.path.join(folder, timestamp + '.json')
    client_hdfs.write(output_path, json.dumps(pcap_json))
    
def multiprocessing_parser(pcap, date, ISP):
    s_time = time.time()
    p = pcap_parser(pcap)
    timestamp = pcap.split(".")[-1]
    pcap_json = p.proc()
    folder_basename = "pcap_json"
    folder = os.path.join(folder_basename, date, ISP)
    write2HDFS(folder, timestamp, pcap_json)
    
if __name__=="__main__":
    s_time = time.time()
    #pcap_dir_path = "/home/antslab/NAS2_RAID6/pcap_process/2020_01_06/中華電信/snort.2020-01-06_dir/"
    pcap_dir_path = sys.argv[1]
    ISP = pcap_dir_path.split("/")[-3]
    date = pcap_dir_path.split("/")[-4]
    file_regex = r'snort\.log\.[\d]+'
    pcap_files = sorted([(os.path.join(pcap_dir_path, file), date, ISP) for file in os.listdir(pcap_dir_path) if re.match(file_regex, file)])
    with Pool(processes=8) as p:
        p.starmap(multiprocessing_parser, pcap_files)
        p.close()
        p.join()
    print("Total time:", time.time()-s_time)
