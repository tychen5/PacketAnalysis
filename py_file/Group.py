#!/usr/bin/env python
# coding: utf-8

# In[1]:


class Group:
    def __init__(self, groupID, number_of_session, number_of_cluster, 
                 number_of_protocol, src_ips, number_of_ip,
                 group_clusters_id, number_of_country, countries):
        self.id = groupID
        self.number_of_session = number_of_session
        self.number_of_cluster = number_of_cluster
        self.number_of_protocol = number_of_protocol
        self.src_ips = src_ips
        self.number_of_ip = number_of_ip
        self.group_clusters_id = group_clusters_id
        self.number_of_country = number_of_country
        self.countries = countries


# In[ ]:




