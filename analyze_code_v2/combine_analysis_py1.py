#!/usr/bin/env python
# coding: utf-8

# # Clusters

import ssdeep
import pickle, sys
import pandas as pd
# pd.set_option('display.max_columns', None)
from tqdm import tqdm


sys.setrecursionlimit(1000000)

# ### Function

isp = '遠傳電信'
time_li = date_li = ['20200106', '20200107', '20200108', '20200109', '20200110', '20200111', '20200112']
protocols_need = proto_li = ['http', 'mysql', 'ftp', 'smb', 'smtp', 'imap', 'pop', 'rpc', 'ssh', 'telnet', 'sip']
time = str(min(time_li))
picture_dir = '/home/antslab/NAS1_RAID6/pcap_inter/' + str(time[:4]) + '_' + str(time[4:6]) + '_' + str(
    time[6:]) + '/' + isp + '/case_pictures/'
file_name = "_".join(sorted(date_li))
min_date = str(min(date_li))
max_date = str(max(date_li))

# ## 畫跨天protocol大小圓圈圖

trend_dict_time_all = {}
trend_dict_country_all = {}
trend_dict_ip_all = {}
trend_dict_ssdeep_all = {}


def draw_trend_pic(date, proto, pickle_dir, trend_dict_time_all=trend_dict_time_all,
                   trend_dict_country_all=trend_dict_country_all, trend_dict_ip_all=trend_dict_ip_all,
                   trend_dict_ssdeep_all=trend_dict_ssdeep_all):
    """
    GOAL: output dict to draw trend-circle picture

    Return: 4 dict for the same proto for the next day
    """
    try:
        (proto_df, proto_df_payload, proto_big_dict, proto_loners, proto_score, proto_cluster_score_dict,
         proto_upgma_dict, stat_df) = pickle.load(open(pickle_dir + str(date) + '_' + str(proto) + '_all.pkl', 'rb'))
    except ValueError:
        try:
            (proto_df, proto_df_payload, proto_big_dict, proto_loners, proto_score, proto_cluster_score_dict,
             proto_upgma_dict, stat_df, df2) = pickle.load(
                open(pickle_dir + str(date) + '_' + str(proto) + '_all.pkl', 'rb'))
        except ValueError:
            try:
                (proto_df, proto_df_payload, proto_big_dict, proto_loners, proto_score, proto_cluster_score_dict,
                 proto_upgma_dict, stat_df) = pickle.load(
                    open(pickle_dir + str(date) + '_' + str(proto) + '_all.pkl', 'rb'))
            except ValueError:
                (proto_df, proto_df_payload, proto_big_dict, proto_loners, proto_score, proto_cluster_score_dict,
                 proto_upgma_dict) = pickle.load(open(pickle_dir + str(date) + '_' + str(proto) + '_all.pkl', 'rb'))
    except FileNotFoundError:
        print("!!File Not Found:", date, proto, "!!")
        return trend_dict_time_all, trend_dict_country_all, trend_dict_ip_all, trend_dict_ssdeep_all

    def ssdeep_compare(target_hash, candidate_df):
        """
        Input1: string of hash
        Input2: dataframe of candidate
        """

        def compare(candidate_hash):
            if type(candidate_hash) == str:
                return ssdeep.compare(target_hash, candidate_hash)
            else:
                score_li = []
                for c_h in candidate_hash:
                    score_li.append(ssdeep.compare(target_hash, c_h))
                return max(score_li)

        return candidate_df.hash.map(compare)

    trend_dict_time = {}
    trend_dict_country = {}
    trend_dict_ip = {}
    trend_dict_ssdeep = {}
    candidate_df = pd.DataFrame(trend_dict_ssdeep_all.items(), columns=['idx', 'hash'])  # 其他已經有的cluster
    for key, value in proto_big_dict.items():
        target = proto_df_payload[proto_df_payload.idx == key]
        target = target.reset_index(drop=True)
        t_len = len(target)
        q2 = int(t_len * 0.5)
        t_q2_key = target.iloc[q2, -1]  # 要跟別人比較的cluster hash
        if trend_dict_ssdeep_all == {}:  # 第一次
            member_li = value[:]

            t_q2_member1 = proto_df_payload[proto_df_payload.idx == member_li[-1]]  # member list最後一個
            t_q2_member1 = t_q2_member1.reset_index(drop=True)
            t_len = len(t_q2_member1)
            q2 = int(t_len * 0.5)
            t_q2_member1 = t_q2_member1.iloc[q2, -1]

            t_q2_member2 = proto_df_payload[proto_df_payload.idx == max(member_li)]  # member list最大的那個
            t_q2_member2 = t_q2_member2.reset_index(drop=True)
            t_len = len(t_q2_member2)
            q2 = int(t_len * 0.5)
            t_q2_member2 = t_q2_member2.iloc[q2, -1]

            trend_dict_ssdeep[str(date) + "_" + str(key)] = [t_q2_key, t_q2_member1,
                                                             t_q2_member2]  # 可以增加hash candidate?
            member_li.append(key)
            select_df = proto_df.loc[member_li]
            time_li = select_df.session_time.tolist()
            trend_dict_time[str(date) + "_" + str(key)] = time_li
            country_li = select_df.country.tolist()
            ip_li = select_df.ip_src.tolist()
            assert len(time_li) == len(country_li) == len(ip_li)
            trend_dict_country[str(date) + "_" + str(key)] = country_li
            trend_dict_ip[str(date) + "_" + str(key)] = ip_li
        else:  # 後面幾次
            candidate_df['score'] = ssdeep_compare(t_q2_key, candidate_df)
            max_score = candidate_df.score.max()
            if max_score < 1:  # 都沒有相近的

                member_li = value[:]

                t_q2_member1 = proto_df_payload[proto_df_payload.idx == member_li[-1]]  # member list最後一個
                t_q2_member1 = t_q2_member1.reset_index(drop=True)
                t_len = len(t_q2_member1)
                q2 = int(t_len * 0.5)
                t_q2_member1 = t_q2_member1.iloc[q2, -1]

                t_q2_member2 = proto_df_payload[proto_df_payload.idx == max(member_li)]  # member list最大的那個
                t_q2_member2 = t_q2_member2.reset_index(drop=True)
                t_len = len(t_q2_member2)
                q2 = int(t_len * 0.5)
                t_q2_member2 = t_q2_member2.iloc[q2, -1]

                trend_dict_ssdeep[str(date) + "_" + str(key)] = [t_q2_key, t_q2_member1, t_q2_member2]
                member_li.append(key)
                select_df = proto_df.loc[member_li]
                time_li = select_df.session_time.tolist()
                trend_dict_time[str(date) + "_" + str(key)] = time_li
                country_li = select_df.country.tolist()
                ip_li = select_df.ip_src.tolist()
                assert len(time_li) == len(country_li) == len(ip_li)
                trend_dict_country[str(date) + "_" + str(key)] = country_li
                trend_dict_ip[str(date) + "_" + str(key)] = ip_li
            elif max_score > 0:  # 有相近的合併到原本的dict
                try:
                    combine_id = candidate_df[candidate_df.score == max_score].idx.tolist()[0]
                except:
                    print(candidate_df, max_score, target)
                ori_ssdeep_list = trend_dict_ssdeep_all[combine_id][:]
                if type(ori_ssdeep_list) == str:
                    ori_ssdeep_list = [ori_ssdeep_list]  # 之前只有一個ssdeep hash
                ori_time_list = trend_dict_time_all[combine_id][:]
                ori_country_list = trend_dict_country_all[combine_id][:]
                ori_ip_list = trend_dict_ip_all[combine_id][:]
                member_li = value[:]

                t_q2_member1 = proto_df_payload[proto_df_payload.idx == member_li[-1]]  # member list最後一個
                t_q2_member1 = t_q2_member1.reset_index(drop=True)
                t_len = len(t_q2_member1)
                q2 = int(t_len * 0.5)
                t_q2_member1 = t_q2_member1.iloc[q2, -1]

                t_q2_member2 = proto_df_payload[proto_df_payload.idx == max(member_li)]  # member list最大的那個
                t_q2_member2 = t_q2_member2.reset_index(drop=True)
                t_len = len(t_q2_member2)
                q2 = int(t_len * 0.5)
                t_q2_member2 = t_q2_member2.iloc[q2, -1]

                t_q2 = [t_q2_key, t_q2_member1, t_q2_member2]
                member_li.append(key)
                select_df = proto_df.loc[member_li]
                time_li = select_df.session_time.tolist()
                ori_time_list.extend(time_li)
                country_li = select_df.country.tolist()
                ip_li = select_df.ip_src.tolist()
                ori_country_list.extend(country_li)
                ori_ip_list.extend(ip_li)
                ori_ssdeep_list.extend(t_q2)  # 我合併進入別人的群，所以把我群的key hash也加入
                assert len(ori_time_list) == len(ori_country_list) == len(ori_ip_list)
                trend_dict_time_all[combine_id] = ori_time_list
                trend_dict_country_all[combine_id] = ori_country_list
                trend_dict_ip_all[combine_id] = ori_ip_list
                trend_dict_ssdeep_all[combine_id] = ori_ssdeep_list
            else:
                print(max_score)
    trend_dict_time_all.update(trend_dict_time)
    trend_dict_country_all.update(trend_dict_country)
    trend_dict_ip_all.update(trend_dict_ip)
    trend_dict_ssdeep_all.update(trend_dict_ssdeep)
    return trend_dict_time_all, trend_dict_country_all, trend_dict_ip_all, trend_dict_ssdeep_all


def sort_li(time_li, country_li):
    """
    GOAL: sort by time (align with time's order)
    Return: list
    """
    sort_country_li = [x for _, x in sorted(zip(time_li, country_li))]
    return sort_country_li

for proto in tqdm(proto_li):
    trend_dict_time_all = {}
    trend_dict_country_all = {}
    trend_dict_ip_all = {}
    trend_dict_ssdeep_all = {}
    for date in date_li:
        pickle_dir = '/home/antslab/NAS1_RAID6/pcap_inter/' + str(date[:4]) + '_' + str(date[4:6]) + '_' + str(
            date[6:]) + '/' + isp + '/case_pickles/'
        trend_dict_time_all, trend_dict_country_all, trend_dict_ip_all, trend_dict_ssdeep_all = draw_trend_pic(date,
                                                                                                               proto,
                                                                                                               pickle_dir,
                                                                                                               trend_dict_time_all,
                                                                                                               trend_dict_country_all,
                                                                                                               trend_dict_ip_all,
                                                                                                               trend_dict_ssdeep_all)
    trend_dict_time_all = {k: v for k, v in
                           sorted(trend_dict_time_all.items(), key=lambda item: len(item[1]), reverse=True)}
    time_df = pd.DataFrame(trend_dict_time_all.items(), columns=['idx', 'timestamp'])
    trend_dict_country_all = {k: v for k, v in
                              sorted(trend_dict_country_all.items(), key=lambda item: len(item[1]), reverse=True)}
    country_df = pd.DataFrame(trend_dict_country_all.items(), columns=['idx', 'country'])
    trend_dict_ip_all = {k: v for k, v in
                         sorted(trend_dict_ip_all.items(), key=lambda item: len(item[1]), reverse=True)}
    ip_df = pd.DataFrame(trend_dict_ip_all.items(), columns=['idx', 'src_ip'])
    ssdeep_df = pd.DataFrame(trend_dict_ssdeep_all.items(), columns=['idx', 'ssdeep'])
    all_df = pd.merge(time_df, country_df, on='idx')
    all_df = pd.merge(all_df, ip_df, on='idx')
    all_df = pd.merge(all_df, ssdeep_df, on='idx')
    all_df['country'] = all_df.apply(lambda x: sort_li(x.timestamp, x.country), axis=1)
    all_df['src_ip'] = all_df.apply(lambda x: sort_li(x.timestamp, x.src_ip), axis=1)
    all_df['timestamp'] = all_df.timestamp.map(sorted)
    file_name = "_".join(sorted(date_li))
    date_li2 = [int(x) for x in date_li]
    min_date = str(min(date_li2))
    pickle.dump(obj=all_df,
                file=open(
                    '/home/antslab/NAS1_RAID6/pcap_inter/' + str(min_date[:4]) + '_' + str(min_date[4:6]) + '_' + str(
                        min_date[6:]) + '/' + isp + '/case_pickles/' + proto + '_trend_df_' + file_name + '.pkl', 'wb'))
    print("Protocol Pattern draw save path:",
          '/home/antslab/NAS1_RAID6/pcap_inter/' + str(min_date[:4]) + '_' + str(min_date[4:6]) + '_' + str(
              min_date[6:]) + '/' + isp + '/case_pickles/' + proto + '_trend_df_' + file_name + '.pkl')

# 輸出cluster之key session的time list

for proto in tqdm(proto_li):
    http_df = pickle.load(open(
        '/home/antslab/NAS1_RAID6/pcap_inter/' + str(min_date[:4]) + '_' + str(min_date[4:6]) + '_' + str(
            min_date[6:]) + '/' + isp + '/case_pickles/' + proto + '_trend_df_' + file_name + '.pkl', 'rb'))

    # 輸出cluster之key session的time list
    wireshark_li = http_df.idx.tolist()  # .head(15)前15大cluster #改!proto
    wireshark_rank = []
    for i, v in enumerate(wireshark_li):
        wireshark_rank.append(i + 1)
    wireshark_rank = [x for _, x in sorted(zip(wireshark_li, wireshark_rank))]
    wireshark_li = sorted(wireshark_li)

    save_path_li = []
    now_date = '00'  # 現在正在處理的日期
    for i, wireshark in zip(wireshark_rank, wireshark_li):
        date = wireshark.split('_')[0]  # 該cluster key的同月份日期
        if date != now_date:  # 新日期才要重讀
            now_date = date

            pickle_dir = '/home/antslab/NAS1_RAID6/pcap_inter/' + str(date[:4]) + '_' + str(date[4:6]) + '_' + str(
                date[6:]) + '/' + isp + '/case_pickles/'
            try:
                (proto_df, proto_df_payload, proto_big_dict, proto_loners, proto_score, proto_cluster_score_dict,
                 proto_upgma_dict, stat_df, df2) = pickle.load(
                    open(pickle_dir + str(date) + '_' + str(proto) + '_all.pkl', 'rb'))
            except ValueError:
                try:
                    (proto_df, proto_df_payload, proto_big_dict, proto_loners, proto_score, proto_cluster_score_dict,
                     proto_upgma_dict, stat_df) = pickle.load(
                        open(pickle_dir + str(date) + '_' + str(proto) + '_all.pkl', 'rb'))
                except ValueError:
                    (proto_df, proto_df_payload, proto_big_dict, proto_loners, proto_score, proto_cluster_score_dict,
                     proto_upgma_dict) = pickle.load(open(pickle_dir + str(date) + '_' + str(proto) + '_all.pkl', 'rb'))
            except FileNotFoundError:
                print("!!File Not Found:", date, proto, "!!")
        idx = wireshark.split('_')[-1]  # 該cluster在該日期該proto的df中的index
        #     else:
        try:
            time_list = proto_df.loc[int(idx), 'session_time_list'].tolist()
        except AttributeError:
            time_list = proto_df.loc[int(idx), 'session_time_list']
        timelist_path = pickle_dir + 'timelist_' + proto + '_large#' + str(i) + '_clusterID#' + str(idx) + '.pkl'
        pickle.dump(file=open(timelist_path, 'wb'), obj=time_list)
        #         print(wireshark,'save in:',timelist_path) #truly save path
        save_path_li.append(timelist_path)
    try:
        first_date = wireshark_li[0].split('_')[0]  # [-2:]
        save_path = '/home/antslab/NAS1_RAID6/pcap_inter/' + str(first_date[:4]) + '_' + str(
            first_date[4:6]) + '_' + str(
            first_date[6:]) + '/' + isp + '/case_pickles/' + proto + '_clusterKey_timelist_paths_' + file_name + '.pkl'
        pickle.dump(file=open(save_path, 'wb'), obj=save_path_li)
        print(proto, ':', save_path)  # for 証鴻 pickle save path
    except IndexError:
        print(proto, "Not Save, because it's empty.")

# #### 新關聯方法
# * 輸出給專家檢視noise clusters

for i, proto in enumerate(proto_li):
    if i == 0:
        all_df = pickle.load(file=open(
            '/home/antslab/NAS1_RAID6/pcap_inter/' + str(min_date[:4]) + '_' + str(min_date[4:6]) + '_' + str(
                min_date[6:]) + '/' + isp + '/case_pickles/' + proto + '_trend_df_' + file_name + '.pkl', 'rb'))  # 改!!)
        all_df['idx'] = all_df['idx'] + '_' + proto
    else:
        temp = pickle.load(file=open(
            '/home/antslab/NAS1_RAID6/pcap_inter/' + str(min_date[:4]) + '_' + str(min_date[4:6]) + '_' + str(
                min_date[6:]) + '/' + isp + '/case_pickles/' + proto + '_trend_df_' + file_name + '.pkl', 'rb'))  # 改!!
        temp['idx'] = temp['idx'] + '_' + proto
        all_df = all_df.append(temp)
all_df = all_df.reset_index(drop=True)
# 首次須先輸出noise pkl給專家，另外處理後才會獲得noise_clusters
pickle_dir = '/home/antslab/NAS1_RAID6/pcap_inter/' + str(min_date[:4]) + '_' + str(min_date[4:6]) + '_' + str(
    min_date[6:]) + '/' + isp + '/case_pickles/'
pickle.dump(
    file=open(pickle_dir + 'clusterName_overview_denoise_df_' + str(min_date) + '_' + str(date_li[-1]) + '.pkl', 'wb'),
    obj=all_df)
print("Denoise path save in:",
      pickle_dir + 'clusterName_overview_denoise_df_' + str(min_date) + '_' + str(date_li[-1]) + '.pkl')
all_df

