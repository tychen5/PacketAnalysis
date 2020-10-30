#!/usr/bin/env python
# coding: utf-8

# In[12]:


import ssdeep
import pickle,os,sys,gc
import pandas as pd
# pd.set_option('display.max_columns', None)
import numpy as np
from tqdm import tqdm
from collections import Counter
import multiprocessing as mp
from multiprocessing import Process, Manager, Pool
import time,datetime
from itertools import chain
import math
from operator import itemgetter
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties
from scipy.cluster.hierarchy import dendrogram, linkage
from sklearn.metrics import jaccard_score
from sklearn.metrics.pairwise import cosine_similarity
import functools
import itertools
import operator
from itertools import chain
sys.setrecursionlimit(1000000)


# ### Function

# In[9]:


isp = '台灣固網'
time_li = ['20200106','20200107','20200108','20200109','20200110','20200111','20200112']
time = str(min(time_li))
picture_dir = '/home/antslab/NAS1_RAID6/pcap_inter/'+str(time[:4])+'_'+str(time[4:6])+'_'+str(time[6:])+'/'+isp+'/case_pictures/'


# 合併三個dict用update來合併以後再通過後面的df function畫圖

# In[13]:



def cluster_rep_hash(proto_big_dict,proto_df_payload,proto_df,proto_loners,knee_point,date='0110',protocol='http'):
    '''
    GOAL: create each cluster's representaion ssdeep hash
    proto_df_payload: from prepare_df() function
    proto_big_dict: from similarity_compare() function
    proto_loners: loner idx list
    knee_point: from get_small_cluster() function
    date & protocol: user_defined cluster name
    
    Return: dict[cluster_name]: ssdeep hash
    '''
    upgma_dict = {}
    for key,value in proto_big_dict.items(): #cluster rep ssdeep
        target = proto_df_payload[proto_df_payload.idx == key]
        target = target.reset_index(drop=True)
        t_len = len(target)
        q2 = int(t_len*0.5)
        q2_hash = target.iloc[q2,-1]
        country = proto_df.loc[key,'country']
        ip = proto_df.loc[key,'ip_src']
        domain = proto_df.loc[key,'domain']
        if len(value)>knee_point:
            upgma_dict[str(protocol)+'_'+str(key)+'_'+str(date)+'_'+str(country)+'_'+str(domain)+'_'+str(ip)] = q2_hash
        else:
            upgma_dict[str(protocol)+'_S_'+str(key)+'_'+str(date)+'_'+str(country)+'_'+str(domain)+'_'+str(ip)] = q2_hash
    for key in proto_loners: #loner ssdeep
        target = proto_df_payload[proto_df_payload.idx == key]
        target = target.reset_index(drop=True)
        t_len = len(target)
        q2 = int(t_len*0.5)
        q2_hash = target.iloc[q2,-1]
        country = proto_df.loc[key,'country']
        ip = proto_df.loc[key,'ip_src']
        domain = proto_df.loc[key,'domain']
        upgma_dict[str(protocol)+'_L_'+str(key)+'_'+str(date)+'_'+str(country)+'_'+str(domain)+'_'+str(ip)] = q2_hash
    return upgma_dict



def pair_wise_score(upgma_dict):
    '''
    GOAL: calculate distance matrix by calculating paire-wise similarity score. 
    and pick upper triangle convert to list
    Input: from cluster_rep_hash() function
    ['cluster']: name
    ['ssdeep']: cluster's representation hash
    
    Return: df=>['c_ssdeep_li']:the hashes list compare to, ['score']:list of distances (upper-triangle, exclude self)
    '''
    def compare(target_hash,candidate_hash_li):
        score_li = []
        for c_hash in candidate_hash_li:
            score_li.append(100-ssdeep.compare(target_hash,c_hash)) #相似度滿分100，轉換成距離最近0
        return score_li
    used_idx = []
    def create_hash_li(t_hash):
        idx_set = set(upgma_df[upgma_df.ssdeep == t_hash].index)#[0]
        same_hash_li = sorted(list(idx_set - set(used_idx)))
        idx = same_hash_li[0]
        used_idx.append(idx)
        return upgma_df.loc[idx+1:]['ssdeep'].tolist()
    upgma_df = pd.DataFrame(upgma_dict.items(),columns=['cluster','ssdeep'])
    upgma_df['c_ssdeep_li'] = upgma_df.ssdeep.map(create_hash_li)
    upgma_df['score'] = upgma_df.apply(lambda x: compare(x.ssdeep, x.c_ssdeep_li), axis=1)
    return upgma_df



def draw_upgma(upgma_df,picture_dir=picture_dir,name='upgma'):
    '''
    GOAL: using upper triangle's distance to draw upgma
    Input: from pair_wise_score() function
    Output: diagram of UPGMA、Z info
    '''
    if not os.path.exists(picture_dir):
        os.makedirs(picture_dir,exist_ok=True) 
    score_li = upgma_df['score'].tolist()
    score_li = list(filter(None, score_li))
    score_li = sum(score_li,[])
    Z = linkage(score_li, 'average')
    fig = plt.figure(figsize=(60, 24)) #(25,10) #(5,2)
    # plt.savefig(fig)
    dn = dendrogram(Z,labels=upgma_df.cluster.tolist())
    plt.savefig(picture_dir+str(name)+'.png', dpi=600, format='png', bbox_inches='tight')
    return dn,Z


# In[14]:


# 大家的pickle_dir都不同0109 0110 0111
# not save?

# time_li = ['02','10','30']
protocols_need = ['http','mysql','ftp','smb','smtp','imap','pop','rpc','ssh','telnet','sip']
# proto = HTTP, FTP, IMAP, MySQL, POP, RPC, SIP, SMB, SMTP, SSH, Telnet
for proto in protocols_need:
    three_dict = {}
    for time in time_li:
        path = '/home/antslab/NAS1_RAID6/pcap_inter/'+str(time[:4])+'_'+str(time[4:6])+'_'+str(time[6:])+'/'+isp+'/case_pickles/'+proto+'_upgma_dict_'+str(time)+'.pkl'
        temp = pickle.load(open(path,'rb'))
        three_dict.update(temp)


    loner_dict = {}
    for k,v in three_dict.items():
        if '_L_' in k:
            loner_dict[k]=v
        if '_S_' in k:
            loner_dict[k] =v
    time_li2 = [int(x) for x in time_li]
    min_time  = str(min(time_li2))
    max_time = str(max(time_li2))
    filename = "_".join(time_li)
    pickle.dump(obj=(three_dict,loner_dict),file=open('/home/antslab/NAS1_RAID6/pcap_inter/'+str(min_time[:4])+'_'+str(min_time[4:6])+'_'+str(min_time[6:])+'/'+isp+'/case_pickles/combine_dict_loner_dict_'+filename+'.pkl','wb'))
    three_upgma_df = pair_wise_score(three_dict) #改!!
    dn,Z = draw_upgma(three_upgma_df,
               picture_dir='/home/antslab/NAS1_RAID6/pcap_inter/'+str(min_time[:4])+'_'+str(min_time[4:6])+'_'+str(min_time[6:])+'/'+isp+'/case_pictures/' #改!!
               ,name=str(min_time)+'-'+str(max_time)+'_upgma') #改!! 0106-0112_upgma            
loner_dict


# ## 畫跨天protocol大小圖

# In[15]:


trend_dict_time_all = {}
trend_dict_country_all = {}
trend_dict_ip_all = {}
trend_dict_ssdeep_all = {}
def draw_trend_pic(date,proto,pickle_dir,trend_dict_time_all=trend_dict_time_all,trend_dict_country_all=trend_dict_country_all,trend_dict_ip_all=trend_dict_ip_all,trend_dict_ssdeep_all=trend_dict_ssdeep_all):
    '''
    GOAL: output dict to draw trend-circle picture
    
    Return: 4 dict for the same proto for the next day
    '''
    try:
        (proto_df, proto_df_payload,proto_big_dict,proto_loners,proto_score,proto_cluster_score_dict,
         proto_upgma_dict,stat_df) = pickle.load(open(pickle_dir+str(date)+'_'+str(proto)+'_all.pkl','rb'))
    except ValueError:
        try:
            (proto_df, proto_df_payload,proto_big_dict,proto_loners,proto_score,proto_cluster_score_dict,
             proto_upgma_dict,stat_df,df2) = pickle.load(open(pickle_dir+str(date)+'_'+str(proto)+'_all.pkl','rb'))
        except ValueError:
            try:
                (proto_df, proto_df_payload,proto_big_dict,proto_loners,proto_score,proto_cluster_score_dict,
                                        proto_upgma_dict,stat_df) = pickle.load(open(pickle_dir+str(date)+'_'+str(proto)+'_all.pkl','rb'))
            except ValueError:
                (proto_df, proto_df_payload,proto_big_dict,proto_loners,proto_score,proto_cluster_score_dict,
                                        proto_upgma_dict) = pickle.load(open(pickle_dir+str(date)+'_'+str(proto)+'_all.pkl','rb'))
    except FileNotFoundError:
        print("!!File Not Found:",date,proto,"!!")
        return trend_dict_time_all,trend_dict_country_all,trend_dict_ip_all,trend_dict_ssdeep_all


    def ssdeep_compare(target_hash,candidate_df):
        '''
        Input1: string of hash
        Input2: dataframe of candidate
        '''
        def compare(candidate_hash):
            if type(candidate_hash) == str:
                return ssdeep.compare(target_hash,candidate_hash)
            else:
                score_li = []
                for c_h in candidate_hash:
                    score_li.append(ssdeep.compare(target_hash,c_h))
                return max(score_li)
        return candidate_df.hash.map(compare)

    trend_dict_time = {}
    trend_dict_country = {}
    trend_dict_ip = {}
    trend_dict_ssdeep = {}
    candidate_df = pd.DataFrame(trend_dict_ssdeep_all.items(),columns=['idx','hash']) #其他已經有的cluster
    for key,value in proto_big_dict.items():
        target = proto_df_payload[proto_df_payload.idx == key]
        target = target.reset_index(drop=True)
        t_len = len(target)
        q2 = int(t_len*0.5)
        t_q2_key = target.iloc[q2,-1] #要跟別人比較的cluster hash
        if trend_dict_ssdeep_all == {}: #第一次
            member_li = value[:]
            
            t_q2_member1 = proto_df_payload[proto_df_payload.idx == member_li[-1]] # member list最後一個
            t_q2_member1 = t_q2_member1.reset_index(drop=True)
            t_len = len(t_q2_member1)
            q2 = int(t_len*0.5)
            t_q2_member1 = t_q2_member1.iloc[q2,-1]
            
            t_q2_member2 = proto_df_payload[proto_df_payload.idx == max(member_li)] #member list最大的那個
            t_q2_member2 = t_q2_member2.reset_index(drop=True)
            t_len = len(t_q2_member2)
            q2 = int(t_len*0.5)
            t_q2_member2 = t_q2_member2.iloc[q2,-1]
            
            trend_dict_ssdeep[str(date)+"_"+str(key)] = [t_q2_key,t_q2_member1,t_q2_member2] #可以增加hash candidate?
            member_li.append(key)
            select_df = proto_df.loc[member_li]
            time_li = select_df.session_time.tolist()
            trend_dict_time[str(date)+"_"+str(key)] = time_li
            country_li = select_df.country.tolist()
            ip_li = select_df.ip_src.tolist()
            assert len(time_li) == len(country_li) == len(ip_li)
            trend_dict_country[str(date)+"_"+str(key)] = country_li
            trend_dict_ip[str(date)+"_"+str(key)] = ip_li
        else: #後面幾次
            candidate_df['score'] = ssdeep_compare(t_q2_key,candidate_df) 
            max_score = candidate_df.score.max()
            if max_score < 1: #都沒有相近的
                
                member_li = value[:]
                
                t_q2_member1 = proto_df_payload[proto_df_payload.idx == member_li[-1]] # member list最後一個
                t_q2_member1 = t_q2_member1.reset_index(drop=True)
                t_len = len(t_q2_member1)
                q2 = int(t_len*0.5)
                t_q2_member1 = t_q2_member1.iloc[q2,-1]

                t_q2_member2 = proto_df_payload[proto_df_payload.idx == max(member_li)] #member list最大的那個
                t_q2_member2 = t_q2_member2.reset_index(drop=True)
                t_len = len(t_q2_member2)
                q2 = int(t_len*0.5)
                t_q2_member2 = t_q2_member2.iloc[q2,-1]
                
                trend_dict_ssdeep[str(date)+"_"+str(key)] = [t_q2_key,t_q2_member1,t_q2_member2]
                member_li.append(key)
                select_df = proto_df.loc[member_li]
                time_li = select_df.session_time.tolist()
                trend_dict_time[str(date)+"_"+str(key)] = time_li
                country_li = select_df.country.tolist()
                ip_li = select_df.ip_src.tolist()
                assert len(time_li) == len(country_li) == len(ip_li)
                trend_dict_country[str(date)+"_"+str(key)] = country_li
                trend_dict_ip[str(date)+"_"+str(key)] = ip_li
            elif max_score>0: #有相近的合併到原本的dict
                try:
                    combine_id = candidate_df[candidate_df.score == max_score].idx.tolist()[0]
                except:
                    print( candidate_df,max_score,target)
                ori_ssdeep_list = trend_dict_ssdeep_all[combine_id][:]
                if type(ori_ssdeep_list) == str:
                    ori_ssdeep_list = [ori_ssdeep_list] #之前只有一個ssdeep hash
                ori_time_list = trend_dict_time_all[combine_id][:]
                ori_country_list = trend_dict_country_all[combine_id][:]
                ori_ip_list = trend_dict_ip_all[combine_id][:]
                member_li = value[:]
                
                t_q2_member1 = proto_df_payload[proto_df_payload.idx == member_li[-1]] # member list最後一個
                t_q2_member1 = t_q2_member1.reset_index(drop=True)
                t_len = len(t_q2_member1)
                q2 = int(t_len*0.5)
                t_q2_member1 = t_q2_member1.iloc[q2,-1]

                t_q2_member2 = proto_df_payload[proto_df_payload.idx == max(member_li)] #member list最大的那個
                t_q2_member2 = t_q2_member2.reset_index(drop=True)
                t_len = len(t_q2_member2)
                q2 = int(t_len*0.5)
                t_q2_member2 = t_q2_member2.iloc[q2,-1]                
                
                t_q2 = [t_q2_key,t_q2_member1,t_q2_member2]
                member_li.append(key)
                select_df = proto_df.loc[member_li]
                time_li = select_df.session_time.tolist()
                ori_time_list.extend(time_li)
                country_li = select_df.country.tolist()
                ip_li = select_df.ip_src.tolist()
                ori_country_list.extend(country_li)
                ori_ip_list.extend(ip_li)
                ori_ssdeep_list.extend(t_q2) #我合併進入別人的群，所以把我群的key hash也加入
                assert len(ori_time_list) == len(ori_country_list) == len(ori_ip_list)
                trend_dict_time_all[combine_id] = ori_time_list
                trend_dict_country_all[combine_id] = ori_country_list
                trend_dict_ip_all[combine_id] = ori_ip_list
                trend_dict_ssdeep_all[combine_id] = ori_ssdeep_list
            else:
                print(max_score)
#         break #debug
    trend_dict_time_all.update(trend_dict_time)
    trend_dict_country_all.update(trend_dict_country)
    trend_dict_ip_all.update(trend_dict_ip)
    trend_dict_ssdeep_all.update(trend_dict_ssdeep)
    return trend_dict_time_all,trend_dict_country_all,trend_dict_ip_all,trend_dict_ssdeep_all


# In[16]:


def sort_li(time_li, country_li):
    '''
    GOAL: sort by time (align with time's order)
    Return: list
    '''
    sort_country_li = [x for _,x in sorted(zip(time_li,country_li))]
    return sort_country_li


# In[17]:



# 指定跨天日期們
date_li = ["20200106","20200107","20200108","20200109","20200110","20200111","20200112"] #,"0102","0130"
# date_li = ["0102","0106","0107","0108","0109","0110","0111","0112","0130"] #,"0102","0130"
# date_li = ['0102','0130','0110']
# isp = '亞太電信'
proto_li =  ['http','mysql','ftp','smb','smtp','imap','pop','rpc','ssh','telnet','sip']
# proto_li = ['tds']
for proto in tqdm(proto_li):
    trend_dict_time_all = {}
    trend_dict_country_all = {}
    trend_dict_ip_all = {}
    trend_dict_ssdeep_all = {}
    for date in date_li:
        pickle_dir = '/home/antslab/NAS1_RAID6/pcap_inter/'+str(date[:4])+'_'+str(date[4:6])+'_'+str(date[6:])+'/'+isp+'/case_pickles/'
        trend_dict_time_all,trend_dict_country_all,trend_dict_ip_all,trend_dict_ssdeep_all = draw_trend_pic(date,proto,
                                                                                          pickle_dir,trend_dict_time_all,trend_dict_country_all,trend_dict_ip_all,trend_dict_ssdeep_all)
    trend_dict_time_all = {k: v for k, v in sorted(trend_dict_time_all.items(), key=lambda item: len(item[1]),reverse=True)}
    time_df = pd.DataFrame(trend_dict_time_all.items(),columns=['idx','timestamp'])
    trend_dict_country_all = {k: v for k, v in sorted(trend_dict_country_all.items(), key=lambda item: len(item[1]),reverse=True)}
    country_df = pd.DataFrame(trend_dict_country_all.items(),columns=['idx','country'])
    trend_dict_ip_all = {k: v for k, v in sorted(trend_dict_ip_all.items(), key=lambda item: len(item[1]),reverse=True)}
    ip_df =  pd.DataFrame(trend_dict_ip_all.items(),columns=['idx','src_ip'])
    ssdeep_df = pd.DataFrame(trend_dict_ssdeep_all.items(),columns=['idx','ssdeep'])
    all_df = pd.merge(time_df,country_df,on='idx')
    all_df =  pd.merge(all_df,ip_df,on='idx')
    all_df = pd.merge(all_df,ssdeep_df,on='idx')
    all_df['country'] = all_df.apply(lambda x: sort_li(x.timestamp, x.country), axis=1)
    all_df['src_ip'] = all_df.apply(lambda x: sort_li(x.timestamp, x.src_ip), axis=1)
    all_df['timestamp'] = all_df.timestamp.map(sorted)
    file_name = "_".join(sorted(date_li))
    date_li2 = [int(x) for x in date_li]
    min_date = str(min(date_li2))
    pickle.dump(obj=all_df,
                file=open('/home/antslab/NAS1_RAID6/pcap_inter/'+str(min_date[:4])+'_'+str(min_date[4:6])+'_'+str(min_date[6:])+'/'+isp+'/case_pickles/'+proto+'_trend_df_'+file_name+'.pkl','wb'))


# 輸出cluster之key session的time list

# In[18]:


date_li = ["20200106","20200107","20200108","20200109","20200110","20200111","20200112"]
min(date_li)


# In[ ]:


proto_li = ['http','mysql','ftp','smb','smtp','imap','pop','rpc','ssh','telnet','sip']
#'http','smb','telnet','ftp','smtp','mysql','ssh','rpc','imap','pop','sip'
# proto = 'tds' 'tds','http',

# date_li = ["0102","0106","0107","0108","0109","0110","0111","0112","0130"] #,"0102","0130"
date_li = ["20200106","20200107","20200108","20200109","20200110","20200111","20200112"] #,"0102","0130"
# date_li = ['0102','0130','0110']
file_name = "_".join(sorted(date_li))
min_date = str(min(date_li))
for proto in tqdm(proto_li):
    http_df = pickle.load(open('/home/antslab/NAS1_RAID6/pcap_inter/'+str(min_date[:4])+'_'+str(min_date[4:6])+'_'+str(min_date[6:])+'/'+isp+'/case_pickles/'+proto+'_trend_df_'+file_name+'.pkl','rb'))

    #輸出cluster之key session的time list
    wireshark_li = http_df.idx.tolist() #.head(15)前15大cluster #改!proto
    wireshark_rank = []
    for i,v in enumerate(wireshark_li):
        wireshark_rank.append(i+1)
    wireshark_rank = [x for _,x in sorted(zip(wireshark_li,wireshark_rank))]
    wireshark_li = sorted(wireshark_li)

    save_path_li = []
    now_date = '00' #現在正在處理的日期
    for i,wireshark in zip(wireshark_rank,wireshark_li):
        date = wireshark.split('_')[0] #該cluster key的同月份日期
        if date!= now_date: #新日期才要重讀
            now_date = date

            pickle_dir = '/home/antslab/NAS1_RAID6/pcap_inter/'+str(date[:4])+'_'+str(date[4:6])+'_'+str(date[6:])+'/'+isp+'/case_pickles/'
            try:
                (proto_df, proto_df_payload,proto_big_dict,proto_loners,proto_score,proto_cluster_score_dict,
                 proto_upgma_dict,stat_df,df2) = pickle.load(open(pickle_dir+str(date)+'_'+str(proto)+'_all.pkl','rb'))
            except ValueError:
                try:
                    (proto_df, proto_df_payload,proto_big_dict,proto_loners,proto_score,proto_cluster_score_dict,
                                            proto_upgma_dict,stat_df) = pickle.load(open(pickle_dir+str(date)+'_'+str(proto)+'_all.pkl','rb'))
                except ValueError:
                    (proto_df, proto_df_payload,proto_big_dict,proto_loners,proto_score,proto_cluster_score_dict,
                                            proto_upgma_dict) = pickle.load(open(pickle_dir+str(date)+'_'+str(proto)+'_all.pkl','rb'))
            except FileNotFoundError:
                print("!!File Not Found:",date,proto,"!!")
        idx = wireshark.split('_')[-1] #該cluster在該日期該proto的df中的index
        #     else:
        try:
            time_list = proto_df.loc[int(idx),'session_time_list'].tolist()
        except AttributeError:
            time_list = proto_df.loc[int(idx),'session_time_list']
        timelist_path = pickle_dir+'timelist_'+proto+'_large#'+str(i)+'_clusterID#'+str(idx)+'.pkl'
        pickle.dump(file=open(timelist_path,'wb'),obj=time_list)
#         print(wireshark,'save in:',timelist_path) #truly save path
        save_path_li.append(timelist_path)

    first_date = wireshark_li[0].split('_')[0]#[-2:]
    save_path = '/home/antslab/NAS1_RAID6/pcap_inter/'+str(first_date[:4])+'_'+str(first_date[4:6])+'_'+str(first_date[6:])+'/'+isp+'/case_pickles/'+proto+'_clusterKey_timelist_paths_'+file_name+'.pkl'
    pickle.dump(file=open(save_path,'wb'),obj=save_path_li)  
    print(proto,':',save_path) #for 証鴻 pickle save path


# http_df


# #### 新關聯方法
# * topology
#     * 我們會先找所給定期間的指定所有protocols之所有sessions與對應IPs
#     * 接下來會利用此段期間的各IP，去尋找這個IP在這段期間做的手法(攻擊樣態群集)
#     * 找出不同IP所橫跨對應的攻擊樣態群，計算jaccard相似度
#     * 將所採用相似手法(score>thr)的IP群聚

# In[ ]:


#第一次只要跑這格。
proto_li =  ['http','mysql','ftp','smb','smtp','imap','pop','rpc','ssh','telnet','sip'] #改!!'tds',
# date_li2 = ["0106","0107","0108","0109","0110","0111","0112"] 
date_li = ["20200106","20200107","20200108","20200109","20200110","20200111","20200112"]  #改!!
# date_li = ['0102','0130','0110']
file_name = "_".join(sorted(date_li)) #改!!
min_date = str(min(date_li))
max_date = str(max(date_li))
for i,proto in enumerate(proto_li):
    if i==0:
        all_df = pickle.load(file=open('/home/antslab/NAS1_RAID6/pcap_inter/'+str(min_date[:4])+'_'+str(min_date[4:6])+'_'+str(min_date[6:])+'/'+isp+'/case_pickles/'+proto+'_trend_df_'+file_name+'.pkl','rb')) #改!!)
        all_df['idx'] = all_df['idx']+'_'+proto
    else:
        temp = pickle.load(file=open('/home/antslab/NAS1_RAID6/pcap_inter/'+str(min_date[:4])+'_'+str(min_date[4:6])+'_'+str(min_date[6:])+'/'+isp+'/case_pickles/'+proto+'_trend_df_'+file_name+'.pkl','rb')) #改!!
        temp['idx'] = temp['idx']+'_'+proto
        all_df = all_df.append(temp)
all_df = all_df.reset_index(drop=True)
#首次須先輸出noise pkl給証鴻，另外處理後才會獲得noise_clusters
pickle_dir = '/home/antslab/NAS1_RAID6/pcap_inter/'+str(min_date[:4])+'_'+str(min_date[4:6])+'_'+str(min_date[6:])+'/'+isp+'/case_pickles/'
pickle.dump(file=open(pickle_dir+'clusterName_overview_denoise_df_'+str(min_date)+'_'+str(date_li[-1])+'.pkl','wb'),obj=all_df)
print("Denoise path save in:",
      pickle_dir+'clusterName_overview_denoise_df_'+str(min_date)+'_'+str(date_li[-1])+'.pkl')
all_df


# In[ ]:


#注意參數!!第二次可以直接從這邊開始跑。
isp = '亞太電信'
date_li = ["20200106","20200107","20200108","20200109","20200110","20200111","20200112"]  #改!!
file_name = "_".join(sorted(date_li)) #date_li 改!!
min_date = str(min(date_li))
max_date = str(max(date_li))


# In[ ]:


#第二次從這邊跑:
noise_path = '/home/antslab/NAS1_RAID6/pcap_inter/'+str(min_date[:4])+'_'+str(min_date[4:6])+'_'+str(min_date[6:])+'/'+isp+'/case_pickles/noise_cluster.pkl'
denoise_path = '/home/antslab/NAS1_RAID6/pcap_inter/'+str(min_date[:4])+'_'+str(min_date[4:6])+'_'+str(min_date[6:])+'/'+isp+'/case_pickles/denoise_cluster.pkl'
pickle_dir = '/home/antslab/NAS1_RAID6/pcap_inter/'+str(min_date[:4])+'_'+str(min_date[4:6])+'_'+str(min_date[6:])+'/'+isp+'/case_pickles/'
all_df = pickle.load(open(pickle_dir+'clusterName_overview_denoise_df_'+str(min_date)+'_'+str(date_li[-1])+'.pkl','rb'))
noise_clusters = pickle.load(open(noise_path,'rb'))
denoise_clusters = pickle.load(open(denoise_path,'rb'))
assert len(noise_clusters) + len(denoise_clusters) == len(all_df)
all_df = all_df[~all_df.idx.isin(noise_clusters)]
all_df
# noise_clusters


# In[ ]:


#find all ips
all_ips = all_df.src_ip.tolist()
all_ips = sum(all_ips,[])
all_ips = list(set(all_ips))
all_ips = sorted(all_ips)
col_li = all_df.idx.tolist()
jc_matrix = pd.DataFrame(0, index=all_ips, columns=col_li)
col_li


# In[ ]:


for col in tqdm(jc_matrix.columns.tolist()):
    if 'tds' in col: # 統一tds欄位，如果有的話
        select_df = all_df[all_df.idx.str.contains('tds')]
        ip_li = list(select_df.src_ip.values)
        try:
            for ips in ip_li:
                jc_matrix.loc[ips,'tds'] = 1
#             jc_matrix = jc_matrix.drop([col])
        except IndexError:
            print("Didn't load tds protocol to all_ip. SKIPPING!")
            pass
    else:
        select_df = all_df[all_df.idx == col]
        ip_li = list(select_df.src_ip.values)
        for ips in ip_li:      
            jc_matrix.loc[ips,col] = 1
# jc_matrix['np_array'] = list(jc_matrix.values)#.ravel()
jc_matrix


# In[ ]:


jc_matrix_stat = jc_matrix.append(pd.Series(jc_matrix.sum(),name='stat'))
jc_matrix_stat['np_array'] = list(jc_matrix_stat.values)
def sum_arr(npy):
    return sum(npy)
jc_matrix_stat['sum'] = jc_matrix_stat.np_array.apply(sum_arr)
jc_matrix_stat


# In[ ]:


jc_matrix_stat = jc_matrix_stat.drop(['np_array'],axis=1)
# pickle_dir = '/home/antslab/spark_data/pcap_inter/2020_01_06/中華電信/case_pickles/'
pickle.dump(file=open(pickle_dir+'clusters_ips_stat_df_'+str(min_date)+'_'+str(max_date)+'.pkl','wb'),obj=jc_matrix_stat)
print('One hot統計df:',pickle_dir+'clusters_ips_stat_df_'+str(min_date)+'_'+str(max_date)+'.pkl')


# In[ ]:


#濾除col:
jc_matrix_new = jc_matrix.append(pd.Series(jc_matrix.sum(),name='stat'))
col_need = []
for col in jc_matrix_new.columns:
    if col == 'np_array':
        continue
    if jc_matrix_new.loc['stat',col] > 1:
        col_need.append(col)
jc_matrix_new = jc_matrix_new[col_need]
#濾除row:
jc_matrix_new['np_array'] = list(jc_matrix_new.values)#.ravel()
jc_matrix_new['sum'] = jc_matrix_new.np_array.apply(sum_arr)
jc_matrix_new = jc_matrix_new[jc_matrix_new['sum']>1]
jc_matrix_new
# jc_matrix.head(10).to_excel('/home/antslab/spark_data/pcap_inter/2020_01_06/中華電信/case_pickles/clique/picture/one-hot.xlsx')


# In[ ]:


jc_matrix = jc_matrix_new.iloc[0:len(jc_matrix_new)-1]
jc_matrix = jc_matrix.sort_values(['sum'],ascending=False)
jc_matrix = jc_matrix.drop(['sum','np_array'],axis=1)
jc_matrix['np_array'] = list(jc_matrix.values)
jc_matrix


# In[ ]:


#檢查!! 不能有assertion err!!!
def sum_val(npy):
    return sum(npy)
jc_matrix['sum'] = jc_matrix['np_array'].apply(sum_val)
temp = jc_matrix[jc_matrix['sum'] == 0]
weird_ips = temp.index.tolist()
assert len(weird_ips) == 0
jc_matrix = jc_matrix.drop(['sum'],axis=1)
gc.collect()


# In[ ]:


jc_matrix_stat = jc_matrix.append(pd.Series(jc_matrix.sum(),name='stat'))
def sum_arr(npy):
    return sum(npy)
jc_matrix_stat['sum'] = jc_matrix_stat.np_array.apply(sum_arr)
jc_matrix_stat = jc_matrix_stat.drop(['np_array'],axis=1)
pickle.dump(file=open(pickle_dir+'clusters_ips_stat_afterFilter_df_'+str(min_date)+'_'+str(max_date)+'.pkl','wb'),obj=jc_matrix_stat)
print("把col=1,row=1以下的濾掉之統計df:",pickle_dir+'clusters_ips_stat_afterFilter_df_'+str(min_date)+'_'+str(max_date)+'.pkl')
jc_matrix_stat


# In[ ]:


def calc_jac(c_value,t_value):
    '''
    GOAL: 同時考量jaccrd計算方式，與人類直覺計算方式
    '''
    j_s = jaccard_score(c_value, t_value)
    c_s = cosine_similarity([c_value], [t_value])[0][0]
    one_portion = max(sum(c_value),sum(t_value))/len(t_value) #最大長度的1的數量
    final_score = (c_s*one_portion)+(j_s*(1-one_portion))
    return final_score
#     return jaccard_score(c_value, t_value)

def calc_cos(c_value,t_value):
    return cosine_similarity(c_value, t_value)


# In[ ]:


# 不同thr都會需要重跑一次
gc.collect()
thr_li= [0.1,0.5,0.9] #,0.8,0.7,0.6,0.5,0.4,0.3,0.2
for thr in tqdm(thr_li):
    jc_dict = {}
    ip_li = jc_matrix.index.tolist() #pandas
    used_ip = []
    for ip in ip_li:
        if ip in used_ip: #合併過得拿掉 single label
            continue
        t_value = jc_matrix.loc[ip,'np_array']# pandas
        jc_calc = jc_matrix[~jc_matrix.index.isin(used_ip)] #合併過得拿掉 single label
        jc_calc = jc_calc[jc_calc.index != ip] #自己的不比 singleLabel
        jc_calc['jc_score'] = jc_calc.np_array.apply(calc_jac,args=(t_value,)) #得到t跟每個c的分數
        combine_df = jc_calc[jc_calc['jc_score']>thr] #所設定的相似度分數
        c_ips_li = combine_df.index.tolist() #跟這個IP具高度相似度的IPs
        if len(c_ips_li)>0:
            jc_dict[ip] = c_ips_li
            used_ip.extend(c_ips_li) #合併過的不要再比
            used_ip.append(ip) #用過的不要再比

    loner_ip = list(set(ip_li) - set(used_ip))
    min_date = str(min(date_li))
    pickle_path = pickle_dir+'CorrelateIP_APTIP_thr'+str(thr)+'_'+file_name+'.pkl' #改!!
    pickle.dump(obj=(jc_dict,loner_ip),file=open(pickle_path,'wb'))
    print("threshold =",thr,"(jaccard_dictionary,loner_ip) save path:",pickle_path)
    print('集團數量(IP>1,score>'+str(thr)+'):',len(jc_dict),"LonerIP數量:",len(loner_ip))


# In[ ]:


def find(myList,target ):
    return [i for i,j in enumerate(myList) if j == target]
def find_time(indexes,li):
    '''
    一個IP回傳一個time list
    '''
    return list(map(li.__getitem__, indexes))
def find_country(need_index,candidate_li):
    '''
    一個IP只回傳一個country
    '''
    return candidate_li[need_index[0]]
def repeat_idx(ori_li,index):
    return [index]*len(ori_li)


# In[ ]:


get_ipython().run_cell_magic('time', '', "# 綜合所需的表，不同thr只要跑一次 [增加country資訊] [增加loner可使用]\njc_matrix2 = jc_matrix.drop(['np_array'],axis=1)\nori_col = all_df.idx.tolist()\ntds_ori_col = []\nfor col in ori_col:\n    if 'tds' in col:\n        tds_ori_col.append(col)\ndef find2(t_ip): #同個target ip\n    global temp\n    global temp2\n    global t_idx\n    temp = jc_matrix2[jc_matrix2.index == t_ip]\n    t_idx = temp.columns[temp.eq(1).any()]\n#     if 'tds' in t_idx:\n#         t_idx = list(t_idx)\n#         t_idx.extend(tds_ori_col)\n    temp2 = all_df[all_df.idx.isin(t_idx)]\n    temp2['gen'] = temp2.src_ip.apply(find,args=(t_ip,))\n    temp2['time_li'] = temp2.apply(lambda x: find_time(x.gen, x.timestamp), axis=1)\n    temp2['idx_li'] = temp2.apply(lambda x: repeat_idx(x.time_li, x.idx), axis=1)\n    temp2['country'] =  temp2.apply(lambda x: find_country(x.gen, x.country), axis=1)\n#     return temp2['time_li'].tolist() #list of lists\n    return functools.reduce(operator.iconcat, temp2['time_li'].tolist(), []),functools.reduce(operator.iconcat, temp2['idx_li'].tolist(), []), temp2['country'].iloc[0] \n\nip_li = jc_matrix.index.tolist()\nip_df = pd.DataFrame(ip_li,columns=['src_ip'])\nip_df['session_timelist'],ip_df['session_idlist'],ip_df['session_county'] = zip(*ip_df['src_ip'].apply(find2))\npickle.dump(obj=ip_df,file=open(pickle_dir+'CorrelateIP_ALL_ip_df.pkl','wb'))\nip_df")


# INFERENCE
# * 可直接跑

# In[17]:


date_li = ["20200106","20200107","20200108","20200109","20200110","20200111","20200112"] 
file_name = "_".join(sorted(date_li)) #date_li 改!!
thr_li = [0.1,0.5,0.9] #最後的值可以跑後面幾格的statistics

min_date = str(min(date_li))
pickle_dir = '/home/antslab/NAS1_RAID6/pcap_inter/'+str(min_date[:4])+'_'+str(min_date[4:6])+'_'+str(min_date[6:])+'/'+isp+'/case_pickles/'
ip_df = pickle.load(open(pickle_dir+'CorrelateIP_ALL_ip_df.pkl','rb')) #改?

for thr in tqdm(thr_li):
    # 改!!
    pickle_path = pickle_dir+'CorrelateIP_APTIP_thr'+str(thr)+'_'+file_name+'.pkl' #改!!
    # pickle_path = '/home/antslab/spark_data/pcap_inter/2020_01_06/中華電信/case_pickles/'+'CorrelateIP_APTIP_thr0.8_0106_0107_0108_0109_0110_0111_0112.pkl'
    jc_dict,loner_ip = pickle.load(open(pickle_path,'rb'))

    similarity_id_list = []
    timelist_dict_list = []
    clusterlist_dict_list = []
    # country_dict = []
    country_list = []

    for cluster_id, ip_li in jc_dict.items():
        all_ips = ip_li[:]
        all_ips.append(cluster_id)
        temp = ip_df[ip_df.src_ip.isin(all_ips)]
        temp_time = temp.set_index('src_ip')['session_timelist'].to_dict()
        temp_id = temp.set_index('src_ip')['session_idlist'].to_dict()
        temp_country = temp['session_county'].tolist()
        similarity_id_list.append(cluster_id) #僅識別用
        timelist_dict_list.append(temp_time)
        clusterlist_dict_list.append(temp_id)
        country_list.append(temp_country)
    pattern_select_df = pd.DataFrame([similarity_id_list,timelist_dict_list,clusterlist_dict_list,country_list],
                 index=['pattern_key','sessions_time_dict','cluster_id_dict','country_list']).T
    save_path = pickle_dir+'CorrelateIP_DRAW_'+str(thr)+'.pkl'
    pickle.dump(obj=pattern_select_df,file=open(save_path,'wb'))
    print("集團數量(IP>1,score>"+str(thr)+"):",len(jc_dict),"LonerIP數量:",len(loner_ip))
    print('視覺化路徑:',save_path)
pattern_select_df


# #### Statistics

# 找IP在哪裡

# In[ ]:


def find_ip(di):
    if '194.61.24.75' in di.keys():
        return True
    else:
        return False


# In[ ]:


temp = pattern_df[:]
temp['isin'] = temp.sessions_time_dict.map(find_ip)
temp = temp[temp['isin'] == True]
temp


# 欄列統計資料

# In[18]:


#有多少column只有1 (這個行為只有一個人做)
column_df = jc_matrix.drop(['np_array'],axis='columns')
column_df = column_df.sum(axis='index')
column_df = pd.DataFrame(column_df)
column_df = column_df.sort_values(0,ascending=False)
column_df


# In[19]:


col_draw = dict(Counter(column_df[0].tolist()))
col_draw = dict(sorted(col_draw.items()))
file_name = pickle_dir+'BehaviorCluster_ips_statistics'+str(thr)+'_'+str(min_date)+'_'+str(max_date)+'.pkl' #改!!
pickle.dump(file=open(file_name,'wb'),obj=(column_df,col_draw)) #(df,dict)
print("col statistics tuple SAVE IN:",file_name)


# In[20]:


# 有多少row只有1 (這個人只做一件事情)
row_df = jc_matrix.drop(['np_array'],axis='columns')
row_df = row_df.sum(axis='columns')
row_df = pd.DataFrame(row_df)
row_df = row_df.sort_values(0,ascending=False)
row_df


# In[21]:


row_draw = dict(Counter(row_df[0].tolist()))
row_draw = dict(sorted(row_draw.items()))
file_name = pickle_dir+'ip_behaviorCluster_statistics'+str(thr)+'_'+str(min_date)+'_'+str(max_date)+'.pkl' #改!!
pickle.dump(file=open(file_name,'wb'),obj=(row_df,row_draw)) #(df,dict)
print("row statistics SAVE IN:",file_name)


# In[22]:


#每個IP有多少個session?
global ip_session_count 
ip_session_count = {}
def find_sessions_number(ip_li):
    '''
    INPUT: list
    
    '''
    global ip_session_count
    for ip in ip_li:
        try:
            val = ip_session_count[ip]
            ip_session_count[ip] = val+1
        except:
            ip_session_count[ip] = 1
all_df.src_ip.apply(find_sessions_number)
ip_session_df = pd.DataFrame(ip_session_count.items())
print("Total sessions#:",ip_session_df[1].sum())
ip_session_df


# In[23]:


#有m個session(key)的IP有幾個(value)
ip_draw = dict(Counter(ip_session_df[1].tolist()))
ip_draw = dict(sorted(ip_draw.items()))
file_name = pickle_dir+'ip_sessions_statistics'+str(thr)+'.pkl' #改!!
pickle.dump(file=open(file_name,'wb'),obj=ip_draw)
print("有m個session(key)的IP有幾個(value) SAVE IN:",file_name)


# loner ip 所對應的 cluster name

# In[24]:


loner_cluster_dict = {}
jc_matrix2 = jc_matrix.drop(['np_array'],axis='columns')
for ip in loner_ip:
    temp = pd.DataFrame(jc_matrix2.loc[ip])
    temp = temp[temp[ip]==1]
    cluster_name_li = temp.index.tolist()
    loner_cluster_dict[ip] = cluster_name_li
print("LonerIP共涵蓋",len(loner_cluster_dict),"個clusters")
 
loner_cluster_df = pd.DataFrame(loner_cluster_dict.items())
loner_cluster_df[2] = loner_cluster_df[1].map(len)
loner_cluster_df.columns = ['src_ip','cluster_name','cluster_num']
file_name = pickle_dir+'lonerip_clusterName_df'+str(thr)+'.pkl' #改!!
pickle.dump(file=open(file_name,'wb'),obj=loner_cluster_df)
print("loner ip 所對應的 cluster name df SAVE IN:",file_name)   
loner_cluster_df


# In[ ]:


loner_cluster_df.cluster_num.describe()


# 計算國家、IP數量、proto數量、cluster數量

# In[ ]:


cluster_name_dict = pickle.load(open('/home/antslab/NAS2_RAID5/pcap_inter/2020_01_06/中華電信/case_pickles/intention_dict_0106_0112.pkl','rb'))
print(cluster_name_dict.keys())
intention_dict = {}
for in_name,cluster_li in cluster_name_dict.items():
    for cluster in cluster_li:
        intention_dict[cluster] = in_name
print(set(intention_dict.values()))
intention_dict


# In[25]:



def count_ip(di):
    '''
    GOAL: count ip number
    '''
    return len(di)
def count_cluster(di):
    '''
    GOAL: count unique clusters #
    '''
    li =  list(di.values())
    return len(set(functools.reduce(operator.iconcat, li, [])))
def proto_li(di):
    '''
    GOAL: extract protocols names
    Return: unique list
    '''
    li = list(di.values())
    cluster_li = list(set(functools.reduce(operator.iconcat, li, [])))
    proto_li = [x.split('_')[-1] for x in cluster_li]
    return sorted(set(proto_li))
def country_li(li):
    lis = list(set(li))
    lis = [str(x) for x in lis]
    return sorted(lis)
#     return sorted(list(set(li)))
def cluster_li(di):
    '''
    GOAL: extract clusters names
    Return: unique list
    '''
    li = list(di.values())
    cluster_li = list(set(functools.reduce(operator.iconcat, li, [])))
    return sorted(set(cluster_li))
def country_count(li):
    '''
    GOAL: count countries in the group's num
    '''
    count_dict = dict(Counter(li))
    return {k: v for k, v in sorted(count_dict.items(), key=lambda item: item[1],reverse=True)}
def country_portion(di):
    '''
    GOAL: count country's port ion the group
    '''
    all_nums = sum(list(di.values()))
    df = pd.DataFrame(di.items())
    df[1] = df[1]/all_nums
    return df.set_index(0)[1].to_dict()
def main_country(di):
    '''
    GOAL: return main country
    '''
    return list(di.keys())[0]
def cluster_number(di):
    '''
    GOAL: count cluster number in each group
    '''
    li =  list(di.values())
    count_dict = dict(Counter(list(functools.reduce(operator.iconcat, li, []))))
    return {k: v for k, v in sorted(count_dict.items(), key=lambda item: item[1],reverse=True)}
def cluster_portion(di):
    '''
    GOAL: use cluster_num to calculate cluster % in each group
    '''
    all_nums = sum(list(di.values()))
    df = pd.DataFrame(di.items())
    df[1] = df[1]/all_nums
    return df.set_index(0)[1].to_dict()
def intention_number(tmp_di):
    '''
    GOAL: transfer cluster name to intention categories.
    '''
    intention_num = {}
    for c_name,c_num in tmp_di.items():
        try:
            i_name = intention_dict[c_name]
        except KeyError:
            i_name = 'probing'
        try:
            ori_num = intention_num[i_name]
            intention_num[i_name] = ori_num + int(c_num)
        except KeyError:
            intention_num[i_name] = int(c_num)
    return {k: v for k, v in sorted(intention_num.items(), key=lambda item: item[1],reverse=True)}
def intention_portion(di):
    '''
    GOAL: calculate intention category's portion in dict type.
    '''
    all_nums = sum(list(di.values()))
    df = pd.DataFrame(di.items())
    df[1] = df[1]/all_nums
    return df.set_index(0)[1].to_dict()    

pattern_select_df['country_set'] = pattern_select_df.country_list.map(country_li)
pattern_select_df['country_nums'] = pattern_select_df['country_list'].map(country_count)
pattern_select_df['country_portion'] = pattern_select_df['country_nums'].map(country_portion)
pattern_select_df['main_country'] = pattern_select_df['country_nums'].map(main_country)
pattern_select_df['proto_set'] = pattern_select_df.cluster_id_dict.map(proto_li)
pattern_select_df['cluster_set'] = pattern_select_df.cluster_id_dict.map(cluster_li)
pattern_select_df['cluster_nums'] = pattern_select_df.cluster_id_dict.map(cluster_number)
pattern_select_df['cluster_portion'] = pattern_select_df.cluster_nums.map(cluster_portion)
pattern_select_df['intention_nums'] = pattern_select_df.cluster_nums.map(intention_number)
pattern_select_df['intention_portion'] = pattern_select_df.intention_nums.map(intention_portion)
pattern_select_df['ip_num'] = pattern_select_df.cluster_id_dict.map(count_ip)
pattern_select_df['unique_country_num'] = pattern_select_df.country_set.map(count_ip)
pattern_select_df['unique_cluster_num'] = pattern_select_df.cluster_id_dict.map(count_cluster)
pattern_select_df['unique_protocols_num'] = pattern_select_df.proto_set.map(count_ip)
pattern_select_df


# In[ ]:


pattern_select_df.describe()


# In[26]:


# thr=0.1
# pickle_dir = '/home/antslab/spark_data/pcap_inter/2020_01_06/中華電信/case_pickles/'
save_path = pickle_dir+'CorrelateIP_DRAW_stat'+str(thr)+'.pkl'
pickle.dump(obj=pattern_select_df,file=open(save_path,'wb'))
print('IP群統計做圖用df路徑:',save_path)


# loner ip's country

# In[27]:


loner_country_info = ip_df[ip_df.src_ip.isin(loner_ip)]
loner_country_info = loner_country_info.reset_index(drop=True)
loner_country_info


# In[ ]:


loner_country_info.session_county.value_counts().head(60)


# In[28]:


pickle.dump(file=open(pickle_dir+'loner_draw_country'+str(thr)+'.pkl','wb'),obj=loner_country_info)
print("loner df資訊(可畫圖):",pickle_dir+'loner_draw_country'+str(thr)+'.pkl')
loner_country_info


# 手法(clusters)出現在哪些group、出現次數頻率
# * all_df搭配pattern_select_df

# In[29]:


cluster_names_li = all_df.idx.tolist()
pattern_select_df


# In[30]:


all_clusters = pattern_select_df['cluster_set'].tolist()
all_clusters = list(functools.reduce(operator.iconcat, all_clusters, []))
all_clusters = dict(Counter(all_clusters))
all_clusters = {k: v for k, v in sorted(all_clusters.items(), key=lambda item: item[1],reverse=True)}
all_clusters 


# In[31]:


pickle.dump(obj=all_clusters,file=open(pickle_dir+'clusterINgroup_stat_'+str(thr)+'_'+str(min_date)+'_'+str(max_date)+'.pkl','wb')) #改
print("手法(clusters)出現次數頻率:",pickle_dir+'clusterINgroup_stat_'+str(min_date)+'_'+str(max_date)+'.pkl')


# 不同的IP會做哪些事情

# In[32]:


get_ipython().run_cell_magic('time', '', "def find_country(ip):\n    return ip_df[ip_df['src_ip'] == ip]['session_county'].iloc[0]\njc_matrix3 = jc_matrix2.reset_index()\njc_matrix3['country'] = jc_matrix3['index'].map(find_country)")


# In[33]:


jc_matrix_country = jc_matrix3.groupby('country').sum()
jc_matrix_country_final = jc_matrix3.groupby('country').sum()


# In[34]:


jc_matrix_country = jc_matrix3.groupby('country').sum()
jc_matrix_country_final = jc_matrix3.groupby('country').sum()
jc_matrix_country_final['max_behavior'] = jc_matrix_country.idxmax(axis=1)
s = pd.Series(jc_matrix_country.idxmax(axis=0), name="max_country")
jc_matrix_country_final = jc_matrix_country_final.append(s)
pickle.dump(file=open(pickle_dir+'country_behavior_table_'+str(min_date)+'_'+str(max_date)+'.pkl','wb'),obj=jc_matrix_country_final)
print('Country Cluster df save in:',pickle_dir+'country_behavior_table_'+str(min_date)+'_'+str(max_date)+'.pkl')
jc_matrix_country_final


# 將patern select df合併經緯度、抓出ssdeep hash

# In[ ]:


def convert2intention(cluster_name):
    try:
        intention = intention_dict[cluster_name]
    except KeyError:
        intention = 'probing'
    return intention
all_df['intention'] = all_df.idx.apply(convert2intention)
all_df


# In[35]:


get_ipython().run_cell_magic('time', '', "import geoip2.database\nfrom geoip2.errors import AddressNotFoundError\n#改\ncity_reader = geoip2.database.Reader('/home/antslab/NAS1_RAID6/GeoIP2-DB/GeoIP2-City_20200526/GeoIP2-City.mmdb')\ncity_reader_response = dict()\ndef find_lalo_all(ip_li):\n    ip_df = pd.DataFrame(ip_li,columns=['ip'])\n    def find_lalo(ip):\n        try:\n            city_response = city_reader.city(ip)\n            latitude = city_response.location.latitude\n            longitude = city_response.location.longitude\n            return (latitude,longitude)\n        except (AddressNotFoundError,NameError):\n            return ('None','None')\n    ip_df['lalo'] = ip_df['ip'].apply(find_lalo)\n    return ip_df['lalo'].tolist()\nall_df['lalo'] = all_df.src_ip.map(find_lalo_all)\nall_df")


# In[36]:


pickle.dump(file=open(pickle_dir+str(min_date)+'_'+str(max_date)+'_clusterID_time_country_ip_ssdeep.pkl','wb')
            ,obj=all_df)
print("Cluster資訊df path:",
      pickle_dir+str(min_date)+'_'+str(max_date)+'_clusterID_time_country_ip_ssdeep_lalo.pkl')


# In[ ]:


def need_col(gb):
    d = {}
    country_li = gb['country'].tolist() #抓出group by後的country欄位，並把所有值轉換為list
    lalo_li = gb['lalo'].tolist()
    time_li = gb['timestamp'].tolist()
    d['country'] = list(functools.reduce(operator.iconcat, country_li, [])) #合併所有list為一個list
    d['lalo'] = list(functools.reduce(operator.iconcat, lalo_li, []))
    d['timestamp'] = list(functools.reduce(operator.iconcat, time_li, []))
    return pd.Series(d,index=['country','lalo','timestamp'])
def sort_li(time_li, country_li):
    '''
    GOAL: sort by time (align with time's order)
    Return: list
    '''
    sort_country_li = [x for _,x in sorted(zip(time_li,country_li))]
    return sort_country_li
draw_intention_df = all_df.groupby('intention').apply(need_col)
draw_intention_df['country'] = draw_intention_df.apply(lambda x:sort_li(x.timestamp,x.country),axis=1)
draw_intention_df['lalo'] = draw_intention_df.apply(lambda x:sort_li(x.timestamp,x.lalo),axis=1)
draw_intention_df['timestamp'] = draw_intention_df.timestamp.map(sorted)
pickle.dump(file=open(pickle_dir+str(min_date)+'_'+str(max_date)+'_intention_country_lalo_drawdf.pkl','wb'),obj=draw_intention_df)
print("全球視覺化地圖df path:",
      pickle_dir+str(min_date)+'_'+str(max_date)+'_intention_country_lalo_drawdf.pkl')
draw_intention_df


# In[ ]:





# 輸出clique圖的case study (跨天、跨protocol)
# * Deprecated

# In[ ]:


#輸出clique圖的case study (跨天、跨protocol)
clique_dir = '/home/antslab/spark_data/pcap_inter/2020_01_06/中華電信/case_pickles/clique/'
save_path_li = []
file_names_li = next(os.walk(clique_dir))[2]
file_names_li = list(filter(lambda k: 'clique_' in k, file_names_li))
file_names_li = list(filter(lambda k: 'cluster' not in k, file_names_li))
file_names_li = list(filter(lambda k: 'http' not in k, file_names_li))
len(file_names_li)
file_names_li


# In[ ]:


def convert_date(s):
    '''
    將日期加上月份
    '''
    mo = '01' #改?
    date = str(s)
    if len(date)==1:
        return mo+'0'+date
    elif len(date)==2:
        return mo+date
    elif len(date)==4:
        return date


# In[ ]:


#輸出clique圖的case study (跨天、跨protocol)
for file_name in tqdm(file_names_li):
# in_file = '/home/antslab/spark_data/pcap_inter/2020_01_06/中華電信/case_pickles/clique_34459.pkl'
    in_file = clique_dir+file_name
    out_filename = in_file.split('/')[-1].split('.')[0]
#     if out_filename != 'clique_34478': #DEBUG!!
#         continue
    list_tuples = pickle.load(open(in_file,'rb'))
    case_wireshark_df = pd.DataFrame(list_tuples,columns =['Date', 'Protocol', 'SessionTime'])
    case_wireshark_df['Date'] = case_wireshark_df.Date.map(convert_date)
    case_wireshark_df = case_wireshark_df.sort_values(['Date','Protocol'],ascending=[True,True])
    case_wireshark_df = case_wireshark_df.reset_index(drop=True)
    
    date_li = list(set(case_wireshark_df.Date.tolist()))
    date_li = sorted(date_li)
    for i,date in enumerate(date_li):
#         print('===',date,'===') #DEBUG!!!
        date_df = case_wireshark_df[case_wireshark_df.Date == date]
        all_time_li = [] #所有protocl一起存放成一個當案
        proto_li = list(set(date_df.Protocol.tolist()))
        proto_li = sorted(proto_li)
        for proto in proto_li:
#             if proto == 'imap' or proto == 'pop': ##DEBUG
#                 print(proto,date)
            pickle_dir = '/home/antslab/spark_data/pcap_inter/2020_'+str(date[:2])+'_'+str(date[-2:])+'/中華電信/case_pickles/'
            try:
                (proto_df, proto_df_payload,proto_big_dict,proto_loners,proto_score,proto_cluster_score_dict,
                                        proto_upgma_dict,stat_df) = pickle.load(open(pickle_dir+str(date)+'_'+str(proto)+'_all.pkl','rb'))
            except ValueError:
                (proto_df, proto_df_payload,proto_big_dict,proto_loners,proto_score,proto_cluster_score_dict,
                                        proto_upgma_dict) = pickle.load(open(pickle_dir+str(date)+'_'+str(proto)+'_all.pkl','rb'))
            except FileNotFoundError:
#                 print('!!NO FILE:',date,proto,'!!')
                date_tmp = str(int(date)+1)
                if len(date_tmp)==3: #限用同月份
                    date_tmp = '0'+date_tmp
                pickle_dir = '/home/antslab/spark_data/pcap_inter/2020_'+str(date_tmp[:2])+'_'+str(date_tmp[-2:])+'/中華電信/case_pickles/'
                try:
                    (proto_df, proto_df_payload,proto_big_dict,proto_loners,proto_score,proto_cluster_score_dict,
                                            proto_upgma_dict,stat_df) = pickle.load(open(pickle_dir+str(date_tmp)+'_'+str(proto)+'_all.pkl','rb'))
                except ValueError:
                    (proto_df, proto_df_payload,proto_big_dict,proto_loners,proto_score,proto_cluster_score_dict,
                                            proto_upgma_dict) = pickle.load(open(pickle_dir+str(date_tmp)+'_'+str(proto)+'_all.pkl','rb'))
                except FileNotFoundError:
                    print('!!NO FILE:',date_tmp,proto,'!!')
                    continue                

            date_proto_df = date_df[date_df.Protocol == proto]
            session_time_li = date_proto_df.SessionTime.tolist()
            need_df = proto_df[proto_df.session_time.isin(session_time_li)]
            not_today_time = list(set(session_time_li) - set(need_df.session_time.tolist()))
            try:
                time_lists = need_df.session_time_list.tolist()
            except AttributeError:
                time_lists = need_df.session_time_list.values
            time_lists = [list(x) for x in time_lists]
            all_time_li.extend(time_lists)
            if len(not_today_time)>1: #有非今天的session time
                date_tmp = str(int(date)+1)
                if len(date_tmp)==3:
                    date_tmp = '0'+date_tmp
                date_df = case_wireshark_df[case_wireshark_df.Date == date_tmp]
                pickle_dir = '/home/antslab/spark_data/pcap_inter/2020_'+str(date_tmp[:2])+'_'+str(date_tmp[-2:])+'/中華電信/case_pickles/'
                try:
                    (proto_df, proto_df_payload,proto_big_dict,proto_loners,proto_score,proto_cluster_score_dict,
                                            proto_upgma_dict,stat_df) = pickle.load(open(pickle_dir+str(date_tmp)+'_'+str(proto)+'_all.pkl','rb'))
                except ValueError:
                    (proto_df, proto_df_payload,proto_big_dict,proto_loners,proto_score,proto_cluster_score_dict,
                                            proto_upgma_dict) = pickle.load(open(pickle_dir+str(date_tmp)+'_'+str(proto)+'_all.pkl','rb'))
                except FileNotFoundError:
                    print('!!NO FILE:',date_tmp,proto,'!!')
                    continue
                date_proto_df = date_df[date_df.Protocol == proto]
                session_time_li = date_proto_df.SessionTime.tolist()
                need_df = proto_df[proto_df.session_time.isin(session_time_li)]
                try:
                    time_lists = need_df.session_time_list.tolist()
                except AttributeError:
                    time_lists = need_df.session_time_list.values
                time_lists = [list(x) for x in time_lists]
                if len(time_lists)>1:
                    all_time_li.extend(time_lists)                
                
                
        out_path = pickle_dir+out_filename+'_session_time_list.pkl'
        pickle.dump(file=open(out_path,'wb'),obj=all_time_li)
        save_path_li.append(out_path)
#         if 'clique_34478' in out_path: #DEBUG
#             print(out_filename,date,':',out_path)
pickle.dump(obj=save_path_li,file=open(clique_dir+'ALL_session_time_lists.pkl','wb')) #debug
print('Meta Path Save in :',clique_dir+'ALL_session_time_lists.pkl')        
#         print(out_filename,date,':',out_path)
# print(out_filename)
# case_wireshark_df

