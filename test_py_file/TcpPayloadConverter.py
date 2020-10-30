#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import os
import re
import subprocess
import json
import binascii


# In[ ]:


class TcpPayloadConverter:
    def __init__(self, date, isp, session_time_list):
        self.date = date
        # pcap directory
        old_path = "/home/antslab/NAS2_RAID6/pcap_process/2020_01_" + date + "/" + isp + "/snort.2020-01-" + date + "_dir/"
        new_path = "/home/antslab/NAS2_RAID6/pcap_process/2020_01_" + date + "/" + isp + "/pcap_2020_01_" + date +"_dir/"
        if os.path.isdir(old_path):
            self.pcap_dir = old_path
        else:
            self.pcap_dir = new_path
        self.session_time_list = session_time_list

    def findPcapFileByDate(self):
        date = self.date
        pcap_dir = self.pcap_dir
        file_regex = r'snort.log.[\d]+'
        pcap_files = sorted([os.path.join(pcap_dir, file) for file in os.listdir(pcap_dir) if re.match(file_regex, file)])
        return pcap_files
    
    def findCandidate(self):
        pcap_files = self.findPcapFileByDate()
        candidate = []
        for pcap in pcap_files:
            try:
                candidate.append(float(pcap[-10:]))
            except ValueError:
                continue
        return candidate
    
    def find_nearest(self, array, value):
        idx = (np.abs(array - value)).argmin()
        return array[idx-1], array[idx]
    
    def parse(self, pcap, pk_time_list): #, pk_time, out_pcap
        rule = "frame.time_epoch=="
        common = " or frame.time_epoch=="
        rule += common.join(pk_time_list)
#         print(rule)
        if pk_time_list:
            cmd = ["tshark","-r", pcap, "-T", "json" ,"-Y", rule, "-e", "tcp.payload"]
            try:
                p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stdin = subprocess.PIPE)
                (output, err) = p.communicate()
                return json.loads(output)
            except OSError:#: [Errno 7] Argument list too long: 'tshark'
                pass
            except Exception as e:
                print(e)
                
    def getPayload(self):
        prefix = "snort.log."
        session_time_list = self.session_time_list
        session_time_list = np.array([session_time_list])
        payload = []
        print("total session:", len(session_time_list))
        for i in range(len(session_time_list)):
            print("session packets: ", len(session_time_list[i]))
            payload.append([])
            target_pcap = list()
            first = min(session_time_list[i])
            last = max(session_time_list[i])
            candidate = self.findCandidate()
            first_target = [pcap_time for pcap_time in candidate if pcap_time <= first]
            target_pcap.append(self.find_nearest(first_target, first)[0])
            target_pcap.append(self.find_nearest(first_target, first)[1])
            for pcap_time in candidate:
                if first < pcap_time <= last and pcap_time not in target_pcap:
                    target_pcap.append(pcap_time)
            for j in range(len(target_pcap)):
                target = target_pcap[j]
                print("target:",target)
                pcap_file = os.path.join(self.pcap_dir, prefix + str(int(target)))
                pk_time_list = []
                for k in range(len(session_time_list[i])):
                    pk_time = session_time_list[i][k]
                    try:
                        if target_pcap[j] < pk_time < target_pcap[j+1]+1:
                            pk_time_list.append(str(pk_time))
                    except:#when k = len(target_pcap)-1
                        if pk_time > target_pcap[j]:
                            pk_time_list.append(str(pk_time))
                pcap_json = self.parse(pcap_file, pk_time_list)
                try:
                    for l in range(len(pcap_json)):
#                         if float(pcap_json[l]['_source']['layers']['frame.time_epoch'][0]) in session_time_list[i]:
                        try:
                            s_ = pcap_json[l]['_source']['layers']['tcp.payload'][0]
                            s_ = s_.split(":")
#                             print(s_)
                            _s = []
                            for m in s_:
                                _s.append(binascii.unhexlify(m).replace(b'\r',b' ').replace(b'\n', b' ').replace(b'\t', b' '))
                            payload[i].append(b"".join(_s))
                        except Exception as e:
                            continue
                except: #pcap_json NoneType
                    continue
        return payload


# In[ ]:




