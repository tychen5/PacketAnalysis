#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import pickle as pk
import numpy as np
import time
import re
get_ipython().run_line_magic('run', 'TcpPayloadConverter.ipynb')
get_ipython().run_line_magic('run', 'Cluster.ipynb')


# In[ ]:


class ClusterFilter:
    def __init__(self, isp, cluster_overview_df):
        self.isp = isp
        self.df = cluster_overview_df
    def checkClusterPayload(self, clusterPayload):
        noise_regex_1 = b'.*comment=.*'
        for payload in clusterPayload[0]:
            if re.match(noise_regex_1, payload):
                return True
                break
        return False
    def getClusterSessionTimeList(self, date, protocol, clusterID, isp):
        base_path = "/home/antslab/NAS1_RAID6/pcap_inter/2020_01_"
        postfix = "/" + isp + "/case_pickles/"
        timelist_regex = r'timelist\w+#\d+\w+#\d+.pkl'
        session_time_dir = base_path + date + postfix
        # find payload pickle file
        session_time_file = [file for file in os.listdir(session_time_dir) if re.match(timelist_regex, file)]
        for file in session_time_file:
            if file.split("_")[1] == protocol and file.split("#")[2].split(".")[0] == clusterID:
                session_time_path = os.path.join(session_time_dir, file)
                with open(session_time_path, "rb")as f:
                    session_time_list = pk.load(f)
                break
        return session_time_list
    def getClusterPayloadList(self):
        cluster_list = []
        cluster_set = self.df["idx"]
        for cluster in cluster_set:
            s_time = time.time()
            protocol = cluster.split("_")[-1]
            date = cluster.split("_")[0][-2:]
            clusterID = cluster.split("_")[1]
            session_time_list = self.getClusterSessionTimeList(date, protocol, clusterID, isp)
            t = TcpPayloadConverter(date, isp, session_time_list)
            cluster_key_payload = t.getPayload()
            c = Cluster(cluster, cluster_key_payload)
            cluster_list.append(c)
        return cluster_list
    def filtering(self, cluster_list):
        noise_cluster = []
        denoise_cluster = []
        for cluster in cluster_list:
            isNoise = self.checkClusterPayload(cluster.clusterPayload)
            if isNoise:
                noise_cluster.append(cluster.id)
            else:
                denoise_cluster.append(cluster.id)
        return noise_cluster, denoise_cluster
    def saveClusterPayload(self, cluster_list):
        isp = self.isp
        # save clusters
        with open("./pickle/"+ isp + "_clusters_correlateIP_0.9.pkl", "wb")as file:
            pk.dump(cluster_list, file)


# In[ ]:


isp = "中華電信"
with open ("/home/antslab/NAS1_RAID6/pcap_inter/2020_01_06/" + isp + "/case_pickles/clusterName_overview_denoise_df_20200106_20200112.pkl", "rb")as file:
    cluster_overview_df = pk.load(file)
cf = ClusterFilter(isp, cluster_overview_df)
cluster_list = cf.getClusterPayloadList()
cf.saveCusterPayload(cluster_list)
noise_cluster, denoise_cluster = cf.filtering(cluster_list)
#save noise and denoise cluster
with open("/home/antslab/NAS1_RAID6/pcap_inter/2020_01_06/" + isp + "/case_pickles/noise_cluster.pkl", "wb")as file:
    pk.dump(noise_cluster, file)
with open("/home/antslab/NAS1_RAID6/pcap_inter/2020_01_06/" + isp + "/case_pickles/denoise_cluster.pkl", "wb")as file:
    pk.dump(denoise_cluster, file)


# In[ ]:




