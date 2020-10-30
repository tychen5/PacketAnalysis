#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import pickle as pk
import os
import re
from xml.etree.ElementTree import Element, SubElement, Comment, tostring
import numpy as np
import subprocess
import json
import time
import binascii
get_ipython().run_line_magic('run', 'Group.ipynb')
get_ipython().run_line_magic('run', 'Cluster.ipynb')
get_ipython().run_line_magic('run', 'TcpPayloadConverter.ipynb')


# In[ ]:


class GroupXmlConverter:
    def __init__(self, isp, group_df):
        self.isp = isp
        self.group_df = group_df
        self.group_list = None
        self.clusters = None
        
    def getGroups(self):
        group_df = self.group_df
        group_list = []
        for group_id in range(group_df.shape[0]):
            group_cluster_id_set = self.get_cluster_set(group_df, group_id)
            number_of_cluster = len(group_cluster_id_set)
            number_of_session = self.get_number_of_session(group_df, group_id)
            number_of_protocol = self.countProtocol(group_cluster_id_set)
            countries = set(group_df.iloc[group_id][3])
            number_of_country = len(countries)
            src_ips = list(group_df.iloc[group_id][1].keys())
            number_of_ip = len(src_ips)
#             if number_of_ip > 9:
            g = Group(group_id, number_of_session,
                      number_of_cluster, number_of_protocol,
                      src_ips, number_of_ip, group_cluster_id_set, 
                      number_of_country, countries)
            group_list.append(g)
        return group_list
    
#     def get_number_of_country(self, group_df, group_id):
#         return group_df.iloc[group_id][5]
    
    def get_cluster_set(self, group_df, group_id):
        cluster_set = set()
        cluster_id_dict = group_df.iloc[group_id][2]
        for ip in cluster_id_dict:
            for cluster in cluster_id_dict[ip]:
                cluster_set.add(cluster)
        return cluster_set
    
    def get_number_of_session(self, group_df, group_id):
        session_time_dict = group_df.iloc[group_id][1]
        all_time = []
        for ip in session_time_dict:
            all_time.extend(session_time_dict[ip])
        return len(all_time)
    
    def countProtocol(self, group_cluster_id_set):
        protocol_set = set()
        for cluster in group_cluster_id_set:
            protocol = cluster.split("_")[-1]
            protocol_set.add(protocol)
        return len(protocol_set)
    
    def getAllCluster(self):
        group_list = self.group_list
        all_cluster = set()
        for group_id in range(len(group_list)):
            for cluster in group_list[group_id].group_clusters_id:
                all_cluster.add(cluster)
        return all_cluster
    
    def getClusterPayloadList(self):
        cluster_set = self.getAllCluster()
        cluster_list = []
        for cluster in cluster_set:
            protocol = cluster.split("_")[-1]
            date = cluster.split("_")[0][2:]
            clusterID = cluster.split("_")[1]
            session_time_list = self.getClusterSessionTimeList(date, protocol, clusterID)
            t = TcpPayloadConverter(date, session_time_list)
            cluster_key_payload = t.getPayload()
            c = Cluster(cluster, cluster_key_payload)
            cluster_list.append(c)
        return cluster_list
            
    def getClusterSessionTimeList(self, date, protocol, clusterID):
        base_path = "/home/antslab/spark_data/pcap_inter/2020_01_"
        postfix = "/中華電信/case_pickles/"
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
    
    def findCluster(self, cluster_ids):
        clique_clusters = []
        clusters = self.clusters
        for cluster_id in cluster_ids:
            for cluster in clusters:
                if cluster_id == cluster.id:
                    clique_clusters.append(cluster)
                    break
        return clique_clusters
    
    def saveClusterPayload(self):
        clusterPayload = self.clusters
        isp = self.isp
        with open("./pickle/" + isp + "_clusters_correlateIP_0.9.pkl", "wb")as file:
            pk.dump(xmlConverter.clusters, file)

    def convert(self):
        top = Element('top')
        group_list = self.group_list
        for group_id in range(len(group_list)):
            group = group_list[group_id]
            group_xml = SubElement(top, "group")

            group_id_xml = SubElement(group_xml, "group_id")
            group_id_xml.text = str(group.id)

            group_number_of_cluster_xml = SubElement(group_xml, "number_of_clusters")
            group_number_of_cluster_xml.text = str(group.number_of_cluster)

            group_number_of_protocol_xml = SubElement(group_xml, "number_of_protocols")
            group_number_of_protocol_xml.text = str(group.number_of_protocol)
            
            src_ip_xml = SubElement(group_xml, "srcIP")
            for ip in group.src_ips:
                src_ip_sub_xml = SubElement(src_ip_xml, "src_ip")
                src_ip_sub_xml.text = str(ip)

#             group_number_of_country_xml = SubElement(group_xml, "number_of_country")
#             group_number_of_country_xml.text = str(group.number_of_country)
            
            country_xml = SubElement(group_xml, "country")
            for country in group.countries:
                country_sub_xml = SubElement(country_xml, "group_country")
                country_sub_xml.text = str(country)
            
            clusters_id = group.group_clusters_id
            group_clusters = self.findCluster(clusters_id)
            cluster_xml = SubElement(group_xml, "cluster")

            for j in range(len(group_clusters)):
                cluster = group_clusters[j]
                cluster_id_xml = SubElement(cluster_xml, "cluster_id")
                cluster_id_xml.text = str(cluster.id)
                for payload in cluster.clusterPayload[0]:
                    cluster_payload_xml = SubElement(cluster_id_xml, "cluster_key_payload")
                    cluster_payload_xml.text = str(payload)
        return top
    
    def saveXmlFile(self, top, outpath):
        mydata = tostring(top, encoding="unicode")
        with open(outpath, "w")as file:
            file.write(mydata)


# ## Main

# In[ ]:


isp = "中華電信"
with open("/home/antslab/spark_data/pcap_inter/2020_01_06/" + isp + "/case_pickles/CorrelateIP_DRAW_stat0.9.pkl", "rb")as file:
    group_df = pk.load(file)
xmlConverter = GroupXmlConverter(isp, group_df)
xmlConverter.group_list = xmlConverter.getGroups()
# getClusterPayload
xmlConverter.clusters = xmlConverter.getClusterPayloadList()
xmlConverter.saveClusterPayload()
top = xmlConverter.convert()
xmlConverter.saveXmlFile(top, "./xml/top_correlate_0.9_wo_tds_all.xml")

