#!/usr/bin/env python
# coding: utf-8

# # Attack Pattern (IP groups)


import ssdeep
import pickle, os, sys, gc
import pandas as pd
# pd.set_option('display.max_columns', None)
import numpy as np
from tqdm import tqdm
from collections import Counter
import multiprocessing as mp
from multiprocessing import Process, Manager, Pool
import time, datetime
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
import geoip2.database
from geoip2.errors import AddressNotFoundError

sys.setrecursionlimit(1000000)

isp = '遠傳電信'
date_li = ['20200106', '20200107', '20200108', '20200109', '20200110', '20200111', '20200112']
protocols_need = proto_li = ['http', 'mysql', 'ftp', 'smb', 'smtp', 'imap', 'pop', 'rpc', 'ssh', 'telnet', 'sip']
time = str(min(date_li))
picture_dir = '/home/antslab/NAS1_RAID6/pcap_inter/' + str(time[:4]) + '_' + str(time[4:6]) + '_' + str(
    time[6:]) + '/' + isp + '/case_pictures/'
file_name = "_".join(sorted(date_li))
min_date = str(min(date_li))
max_date = str(max(date_li))
noise_path = '/home/antslab/NAS1_RAID6/pcap_inter/' + str(min_date[:4]) + '_' + str(min_date[4:6]) + '_' + str(
    min_date[6:]) + '/' + isp + '/case_pickles/noise_cluster.pkl'
denoise_path = '/home/antslab/NAS1_RAID6/pcap_inter/' + str(min_date[:4]) + '_' + str(min_date[4:6]) + '_' + str(
    min_date[6:]) + '/' + isp + '/case_pickles/denoise_cluster.pkl'
pickle_dir = '/home/antslab/NAS1_RAID6/pcap_inter/' + str(min_date[:4]) + '_' + str(min_date[4:6]) + '_' + str(
    min_date[6:]) + '/' + isp + '/case_pickles/'
thr_li = [0.1, 0.5, 0.9]
city_reader = geoip2.database.Reader('/home/antslab/NAS1_RAID6/GeoIP2-DB/GeoIP2-City_20200526/GeoIP2-City.mmdb')

# #### 新關聯方法
# * topology
#     * 我們會先找所給定期間的指定所有protocols之所有sessions與對應IPs
#     * 接下來會利用此段期間的各IP，去尋找這個IP在這段期間做的手法(攻擊樣態群集)
#     * 找出不同IP所橫跨對應的攻擊樣態群，計算jaccard相似度
#     * 將所採用相似手法(score>thr)的IP群聚

# ### Function


# 第二次跑:
all_df = pickle.load(
    open(pickle_dir + 'clusterName_overview_denoise_df_' + str(min_date) + '_' + str(date_li[-1]) + '.pkl', 'rb'))
noise_clusters = pickle.load(open(noise_path, 'rb'))
denoise_clusters = pickle.load(open(denoise_path, 'rb'))
assert len(noise_clusters) + len(denoise_clusters) == len(all_df)


def cut_protocol(cluster_id):
    """
    GOAL: 將cluster index轉換為protocol名稱
    """
    return cluster_id.split("_")[-1]


def count_sessions_num(time_li):
    """
    GOAL: 依據timestamp list計算每個cluster所具有的session數量
    """
    return len(time_li)


all_df['protocol'] = all_df.idx.map(cut_protocol)
all_df['session_num'] = all_df.timestamp.map(count_sessions_num)
print(isp, "經濾除noiseClusters後在", min_date, "至", max_date, "的期間中各protocols的session數量:")
temp = pd.DataFrame(all_df.groupby('protocol')['session_num'].sum()).sort_values('session_num', ascending=False)
print(temp)

# find all ips
all_ips = all_df.src_ip.tolist()
all_ips = sum(all_ips, [])
all_ips = list(set(all_ips))
all_ips = sorted(all_ips)
col_li = all_df.idx.tolist()
jc_matrix = pd.DataFrame(0, index=all_ips, columns=col_li)

for col in tqdm(jc_matrix.columns.tolist()):
    if 'tds' in col:  # 統一tds欄位，如果有的話
        select_df = all_df[all_df.idx.str.contains('tds')]
        ip_li = list(select_df.src_ip.values)
        try:
            for ips in ip_li:
                jc_matrix.loc[ips, 'tds'] = 1
        except IndexError:
            print("Didn't load tds protocol to all_ip. SKIPPING!")
            pass
    else:
        select_df = all_df[all_df.idx == col]
        ip_li = list(select_df.src_ip.values)
        for ips in ip_li:
            jc_matrix.loc[ips, col] = 1

jc_matrix_stat = jc_matrix.append(pd.Series(jc_matrix.sum(), name='stat'))
jc_matrix_stat['np_array'] = list(jc_matrix_stat.values)


def sum_arr(npy):
    return sum(npy)


jc_matrix_stat['sum'] = jc_matrix_stat.np_array.apply(sum_arr)

jc_matrix_stat = jc_matrix_stat.drop(['np_array'], axis=1)
# pickle_dir = '/home/antslab/spark_data/pcap_inter/2020_01_06/中華電信/case_pickles/'
pickle.dump(file=open(pickle_dir + 'clusters_ips_stat_df_' + str(min_date) + '_' + str(max_date) + '.pkl', 'wb'),
            obj=jc_matrix_stat)
print('One hot統計df:', pickle_dir + 'clusters_ips_stat_df_' + str(min_date) + '_' + str(max_date) + '.pkl')

# 濾除col:
jc_matrix_new = jc_matrix.append(pd.Series(jc_matrix.sum(), name='stat'))
col_need = []
for col in jc_matrix_new.columns:
    if col == 'np_array':
        continue
    if jc_matrix_new.loc['stat', col] > 1:
        col_need.append(col)
jc_matrix_new = jc_matrix_new[col_need]
# 濾除row:
jc_matrix_new['np_array'] = list(jc_matrix_new.values)  # .ravel()
jc_matrix_new['sum'] = jc_matrix_new.np_array.apply(sum_arr)
jc_matrix_new = jc_matrix_new[jc_matrix_new['sum'] > 1]

jc_matrix = jc_matrix_new.iloc[0:len(jc_matrix_new) - 1]
jc_matrix = jc_matrix.sort_values(['sum'], ascending=False)
jc_matrix = jc_matrix.drop(['sum', 'np_array'], axis=1)
jc_matrix['np_array'] = list(jc_matrix.values)


def sum_val(npy):
    return sum(npy)


jc_matrix['sum'] = jc_matrix['np_array'].apply(sum_val)
temp = jc_matrix[jc_matrix['sum'] == 0]
weird_ips = temp.index.tolist()
assert len(weird_ips) == 0  # 檢查!! 不能有assertion err!!!
jc_matrix = jc_matrix.drop(['sum'], axis=1)
gc.collect()

jc_matrix_stat = jc_matrix.append(pd.Series(jc_matrix.sum(), name='stat'))


def sum_arr(npy):
    return sum(npy)


jc_matrix_stat['sum'] = jc_matrix_stat.np_array.apply(sum_arr)
jc_matrix_stat = jc_matrix_stat.drop(['np_array'], axis=1)
pickle.dump(
    file=open(pickle_dir + 'clusters_ips_stat_afterFilter_df_' + str(min_date) + '_' + str(max_date) + '.pkl', 'wb'),
    obj=jc_matrix_stat)
print("把col=1,row=1以下的濾掉之統計df:",
      pickle_dir + 'clusters_ips_stat_afterFilter_df_' + str(min_date) + '_' + str(max_date) + '.pkl')


# In[ ]:


def calc_jac(c_value, t_value):
    '''
    GOAL: 同時考量jaccrd計算方式，與人類直覺計算方式
    '''
    j_s = jaccard_score(c_value, t_value)
    c_s = cosine_similarity([c_value], [t_value])[0][0]
    one_portion = max(sum(c_value), sum(t_value)) / len(t_value)  # 最大長度的1的數量
    final_score = (c_s * one_portion) + (j_s * (1 - one_portion))
    return final_score


def calc_cos(c_value, t_value):
    return cosine_similarity(c_value, t_value)


# 不同thr都會需要重跑一次
gc.collect()
for thr in tqdm(thr_li):
    jc_dict = {}
    ip_li = jc_matrix.index.tolist()  # pandas
    used_ip = []
    for ip in ip_li:
        if ip in used_ip:  # 合併過得拿掉 single label
            continue
        t_value = jc_matrix.loc[ip, 'np_array']  # pandas
        jc_calc = jc_matrix[~jc_matrix.index.isin(used_ip)]  # 合併過得拿掉 single label
        jc_calc = jc_calc[jc_calc.index != ip]  # 自己的不比 singleLabel
        jc_calc['jc_score'] = jc_calc.np_array.apply(calc_jac, args=(t_value,))  # 得到t跟每個c的分數
        combine_df = jc_calc[jc_calc['jc_score'] > thr]  # 所設定的相似度分數
        c_ips_li = combine_df.index.tolist()  # 跟這個IP具高度相似度的IPs
        if len(c_ips_li) > 0:
            jc_dict[ip] = c_ips_li
            used_ip.extend(c_ips_li)  # 合併過的不要再比
            used_ip.append(ip)  # 用過的不要再比

    loner_ip = list(set(ip_li) - set(used_ip))
    min_date = str(min(date_li))
    pickle_path = pickle_dir + 'CorrelateIP_APTIP_thr' + str(thr) + '_' + file_name + '.pkl'  # 改!!
    pickle.dump(obj=(jc_dict, loner_ip), file=open(pickle_path, 'wb'))
    print("threshold =", thr, "(jaccard_dictionary,loner_ip) save path:", pickle_path)
    print('集團數量(IP>1,score>' + str(thr) + '):', len(jc_dict), "LonerIP數量:", len(loner_ip))


def find(myList, target):
    return [i for i, j in enumerate(myList) if j == target]


def find_time(indexes, li):
    """
    一個IP回傳一個time list
    """
    return list(map(li.__getitem__, indexes))


def find_country(need_index, candidate_li):
    """
    一個IP只回傳一個country
    """
    return candidate_li[need_index[0]]


def repeat_idx(ori_li, index):
    return [index] * len(ori_li)


jc_matrix2 = jc_matrix.drop(['np_array'], axis=1)
ori_col = all_df.idx.tolist()
tds_ori_col = []
for col in ori_col:
    if 'tds' in col:
        tds_ori_col.append(col)


def find2(t_ip):  # 同個target ip
    global temp
    global temp2
    global t_idx
    temp = jc_matrix2[jc_matrix2.index == t_ip]
    t_idx = temp.columns[temp.eq(1).any()]

    temp2 = all_df[all_df.idx.isin(t_idx)]
    temp2['gen'] = temp2.src_ip.apply(find, args=(t_ip,))
    temp2['time_li'] = temp2.apply(lambda x: find_time(x.gen, x.timestamp), axis=1)
    temp2['idx_li'] = temp2.apply(lambda x: repeat_idx(x.time_li, x.idx), axis=1)
    temp2['country'] = temp2.apply(lambda x: find_country(x.gen, x.country), axis=1)
    return functools.reduce(operator.iconcat, temp2['time_li'].tolist(), []), functools.reduce(operator.iconcat,
                                                                                               temp2['idx_li'].tolist(),
                                                                                               []), \
           temp2['country'].iloc[0]


ip_li = jc_matrix.index.tolist()
ip_df = pd.DataFrame(ip_li, columns=['src_ip'])
ip_df['session_timelist'], ip_df['session_idlist'], ip_df['session_county'] = zip(*ip_df['src_ip'].apply(find2))
pickle.dump(obj=ip_df, file=open(pickle_dir + 'CorrelateIP_ALL_ip_df.pkl', 'wb'))

# INFERENCE
# * 可直接跑


# ip_df = pickle.load(open(pickle_dir+'CorrelateIP_ALL_ip_df.pkl','rb')) #check point
for thr in tqdm(thr_li):
    pickle_path = pickle_dir + 'CorrelateIP_APTIP_thr' + str(thr) + '_' + file_name + '.pkl'  # pickle路徑
    jc_dict, loner_ip = pickle.load(open(pickle_path, 'rb'))

    similarity_id_list = []
    timelist_dict_list = []
    clusterlist_dict_list = []
    country_list = []

    for cluster_id, ip_li in jc_dict.items():
        all_ips = ip_li[:]
        all_ips.append(cluster_id)
        temp = ip_df[ip_df.src_ip.isin(all_ips)]
        temp_time = temp.set_index('src_ip')['session_timelist'].to_dict()
        temp_id = temp.set_index('src_ip')['session_idlist'].to_dict()
        #     temp_country = temp.set_index('src_ip')['country'].to_dict()
        temp_country = temp['session_county'].tolist()
        similarity_id_list.append(cluster_id)  # 僅識別用
        timelist_dict_list.append(temp_time)
        clusterlist_dict_list.append(temp_id)
        country_list.append(temp_country)
    pattern_select_df = pd.DataFrame([similarity_id_list, timelist_dict_list, clusterlist_dict_list, country_list],
                                     index=['pattern_key', 'sessions_time_dict', 'cluster_id_dict', 'country_list']).T
    save_path = pickle_dir + 'CorrelateIP_DRAW_' + str(thr) + '.pkl'
    pickle.dump(obj=pattern_select_df, file=open(save_path, 'wb'))
    print("集團數量(IP>1,score>" + str(thr) + "):", len(jc_dict), "LonerIP數量:", len(loner_ip))
    print('視覺化路徑:', save_path)

# #### Statistics Section


# 每個IP有多少個session?
global ip_session_count
ip_session_count = {}


def find_sessions_number(ip_li):
    """
    INPUT: list

    """
    global ip_session_count
    for ip in ip_li:
        try:
            val = ip_session_count[ip]
            ip_session_count[ip] = val + 1
        except:
            ip_session_count[ip] = 1


all_df.src_ip.apply(find_sessions_number)
ip_session_df = pd.DataFrame(ip_session_count.items())
print("Total sessions#:", ip_session_df[1].sum())

# 有m個session(key)的IP有幾個(value)
ip_draw = dict(Counter(ip_session_df[1].tolist()))
ip_draw = dict(sorted(ip_draw.items()))
file_name = pickle_dir + 'ip_sessions_statistics' + str(thr) + '.pkl'  # 改!!
pickle.dump(file=open(file_name, 'wb'), obj=ip_draw)
print("有m個session(key)的IP有幾個(value) SAVE IN:", file_name)

# loner ip 所對應的 cluster name


loner_cluster_dict = {}
jc_matrix2 = jc_matrix.drop(['np_array'], axis='columns')
for ip in loner_ip:
    temp = pd.DataFrame(jc_matrix2.loc[ip])
    temp = temp[temp[ip] == 1]
    cluster_name_li = temp.index.tolist()
    loner_cluster_dict[ip] = cluster_name_li
print("LonerIP共涵蓋", len(loner_cluster_dict), "個clusters")

loner_cluster_df = pd.DataFrame(loner_cluster_dict.items())
loner_cluster_df[2] = loner_cluster_df[1].map(len)
loner_cluster_df.columns = ['src_ip', 'cluster_name', 'cluster_num']
file_name = pickle_dir + 'lonerip_clusterName_df' + str(thr) + '.pkl'  # 改!!
pickle.dump(file=open(file_name, 'wb'), obj=loner_cluster_df)
print("loner ip 所對應的 cluster name df SAVE IN:", file_name)

# 計算國家、IP數量、proto數量、cluster數量

# 需要各Cluster所對應之mitre轉換!
cluster_name_dict = pickle.load(
    open('/home/antslab/NAS2_RAID5/pcap_inter/2020_01_06/中華電信/case_pickles/intention_dict_0106_0112.pkl', 'rb'))
print(cluster_name_dict.keys())
intention_dict = {}
for in_name, cluster_li in cluster_name_dict.items():
    for cluster in cluster_li:
        intention_dict[cluster] = in_name


def count_ip(di):
    """
    GOAL: count ip number
    """
    return len(di)


def count_cluster(di):
    """
    GOAL: count unique clusters #
    """
    li = list(di.values())
    return len(set(functools.reduce(operator.iconcat, li, [])))


def proto_li(di):
    """
    GOAL: extract protocols names
    Return: unique list
    """
    li = list(di.values())
    cluster_li = list(set(functools.reduce(operator.iconcat, li, [])))
    proto_li = [x.split('_')[-1] for x in cluster_li]
    return sorted(set(proto_li))


def country_li(li):
    lis = list(set(li))
    lis = [str(x) for x in lis]
    return sorted(lis)


def cluster_li(di):
    """
    GOAL: extract clusters names
    Return: unique list
    """
    li = list(di.values())
    cluster_li = list(set(functools.reduce(operator.iconcat, li, [])))
    return sorted(set(cluster_li))


def country_count(li):
    """
    GOAL: count countries in the group's num
    """
    count_dict = dict(Counter(li))
    return {k: v for k, v in sorted(count_dict.items(), key=lambda item: item[1], reverse=True)}


def country_portion(di):
    """
    GOAL: count country's port ion the group
    """
    all_nums = sum(list(di.values()))
    df = pd.DataFrame(di.items())
    df[1] = df[1] / all_nums
    return df.set_index(0)[1].to_dict()


def main_country(di):
    """
    GOAL: return main country
    """
    return list(di.keys())[0]


def cluster_number(di):
    """
    GOAL: count cluster number in each group
    """
    li = list(di.values())
    count_dict = dict(Counter(list(functools.reduce(operator.iconcat, li, []))))
    return {k: v for k, v in sorted(count_dict.items(), key=lambda item: item[1], reverse=True)}


def cluster_portion(di):
    """
    GOAL: use cluster_num to calculate cluster % in each group
    """
    all_nums = sum(list(di.values()))
    df = pd.DataFrame(di.items())
    df[1] = df[1] / all_nums
    return df.set_index(0)[1].to_dict()


def intention_number(tmp_di):
    """
    GOAL: transfer cluster name to intention categories.
    """
    intention_num = {}
    for c_name, c_num in tmp_di.items():
        try:
            i_name = intention_dict[c_name]
        except KeyError:
            i_name = 'probing'
        try:
            ori_num = intention_num[i_name]
            intention_num[i_name] = ori_num + int(c_num)
        except KeyError:
            intention_num[i_name] = int(c_num)
    return {k: v for k, v in sorted(intention_num.items(), key=lambda item: item[1], reverse=True)}


def intention_portion(di):
    """
    GOAL: calculate intention category's portion in dict type.
    """
    all_nums = sum(list(di.values()))
    df = pd.DataFrame(di.items())
    df[1] = df[1] / all_nums
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

save_path = pickle_dir + 'CorrelateIP_DRAW_stat' + str(thr) + '.pkl'
pickle.dump(obj=pattern_select_df, file=open(save_path, 'wb'))
print('IP群統計做圖用df路徑:', save_path)

# loner ip's country
loner_country_info = ip_df[ip_df.src_ip.isin(loner_ip)]
loner_country_info = loner_country_info.reset_index(drop=True)

pickle.dump(file=open(pickle_dir + 'loner_draw_country' + str(thr) + '.pkl', 'wb'), obj=loner_country_info)
print("loner df資訊(可畫圖):", pickle_dir + 'loner_draw_country' + str(thr) + '.pkl')

# 手法(clusters)出現在哪些group、出現次數頻率
# * all_df搭配pattern_select_df
cluster_names_li = all_df.idx.tolist()
all_clusters = pattern_select_df['cluster_set'].tolist()
all_clusters = list(functools.reduce(operator.iconcat, all_clusters, []))
all_clusters = dict(Counter(all_clusters))
all_clusters = {k: v for k, v in sorted(all_clusters.items(), key=lambda item: item[1], reverse=True)}

pickle.dump(obj=all_clusters, file=open(
    pickle_dir + 'clusterINgroup_stat_' + str(thr) + '_' + str(min_date) + '_' + str(max_date) + '.pkl', 'wb'))  # 改
print("手法(clusters)出現次數頻率:", pickle_dir + 'clusterINgroup_stat_' + str(min_date) + '_' + str(max_date) + '.pkl')


# 不同的IP會做哪些事情

def find_country(ip):
    return ip_df[ip_df['src_ip'] == ip]['session_county'].iloc[0]


jc_matrix3 = jc_matrix2.reset_index()
jc_matrix3['country'] = jc_matrix3['index'].map(find_country)

jc_matrix_country = jc_matrix3.groupby('country').sum()
jc_matrix_country_final = jc_matrix3.groupby('country').sum()

jc_matrix_country = jc_matrix3.groupby('country').sum()
jc_matrix_country_final = jc_matrix3.groupby('country').sum()
jc_matrix_country_final['max_behavior'] = jc_matrix_country.idxmax(axis=1)
s = pd.Series(jc_matrix_country.idxmax(axis=0), name="max_country")
jc_matrix_country_final = jc_matrix_country_final.append(s)
pickle.dump(file=open(pickle_dir + 'country_behavior_table_' + str(min_date) + '_' + str(max_date) + '.pkl', 'wb'),
            obj=jc_matrix_country_final)
print('Country Cluster df save in:',
      pickle_dir + 'country_behavior_table_' + str(min_date) + '_' + str(max_date) + '.pkl')


# 將patern select df合併經緯度、抓出ssdeep hash
# Need intention dict!
def convert2intention(cluster_name):
    try:
        intention = intention_dict[cluster_name]
    except KeyError:
        intention = 'probing'
    return intention


all_df['intention'] = all_df.idx.apply(convert2intention)

city_reader_response = dict()


def find_lalo_all(ip_li):
    ip_df = pd.DataFrame(ip_li, columns=['ip'])

    def find_lalo(ip):
        try:
            city_response = city_reader.city(ip)
            latitude = city_response.location.latitude
            longitude = city_response.location.longitude
            return (latitude, longitude)
        except (AddressNotFoundError, NameError):
            return ('None', 'None')

    ip_df['lalo'] = ip_df['ip'].apply(find_lalo)
    return ip_df['lalo'].tolist()


all_df['lalo'] = all_df.src_ip.map(find_lalo_all)


pickle.dump(file=open(pickle_dir + str(min_date) + '_' + str(max_date) + '_clusterID_time_country_ip_ssdeep.pkl', 'wb')
            , obj=all_df)
print("Cluster資訊df path:",
      pickle_dir + str(min_date) + '_' + str(max_date) + '_clusterID_time_country_ip_ssdeep_lalo.pkl')


# Need intention dict!
def need_col(gb):
    d = {}
    country_li = gb['country'].tolist()  # 抓出group by後的country欄位，並把所有值轉換為list
    lalo_li = gb['lalo'].tolist()
    time_li = gb['timestamp'].tolist()
    d['country'] = list(functools.reduce(operator.iconcat, country_li, []))  # 合併所有list為一個list
    d['lalo'] = list(functools.reduce(operator.iconcat, lalo_li, []))
    d['timestamp'] = list(functools.reduce(operator.iconcat, time_li, []))
    return pd.Series(d, index=['country', 'lalo', 'timestamp'])


def sort_li(time_li, country_li):
    """
    GOAL: sort by time (align with time's order)
    Return: list
    """
    sort_country_li = [x for _, x in sorted(zip(time_li, country_li))]
    return sort_country_li


# #Need Fix intention dict
draw_intention_df = all_df.groupby('intention').apply(need_col)
draw_intention_df['country'] = draw_intention_df.apply(lambda x: sort_li(x.timestamp, x.country), axis=1)
draw_intention_df['lalo'] = draw_intention_df.apply(lambda x: sort_li(x.timestamp, x.lalo), axis=1)
draw_intention_df['timestamp'] = draw_intention_df.timestamp.map(sorted)
pickle.dump(file=open(pickle_dir + str(min_date) + '_' + str(max_date) + '_intention_country_lalo_drawdf.pkl', 'wb'),
            obj=draw_intention_df)
print("全球視覺化地圖df path:",
      pickle_dir + str(min_date) + '_' + str(max_date) + '_intention_country_lalo_drawdf.pkl')
draw_intention_df
