#!/usr/bin/env python
# coding: utf-8

# tar -C /tmp/ayu -zvxf xyz.tar.gz

# In[1]:


import os,sys,pickle,time
import pandas as pd
import numpy as np
import subprocess
from multiprocessing import Pool 
import shutil
from tqdm import tqdm


# In[3]:


tgz_dir = "../../RAID5/pcap/"
decompress_dir = "../../RAID6/pcap_process/"
all_dates = next(os.walk(tgz_dir))[1]
all_dates = sorted(all_dates)
all_dates


# In[4]:


def parallel_untar(in_file,out_dir):
    test_dir = out_dir.split('/')
    test_dir = test_dir[:3]
    test_dir = "/".join(test_dir)
    total, used, free = shutil.disk_usage(test_dir)
    if (free<total*0.01) or (free // (2**30) < 130):
#         cmd = ['rmdir',out_dir]
#         p = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=False)
#         out, err = p.communicate()
#         print("!Error:", err, '!')
        print('Disk not enough space ERR:',in_file,out_dir)
        return out_dir
    else:
        if not os.path.exists(out_dir):
            os.makedirs(out_dir, exist_ok=True)
        
        
        #cat pcap_2020_04_18_part* > pcap_2020_04_18.tar.gz # 合併
        #cat pcap_2020_04_18_part* | tar -C out_dir -zxvf #解壓
        
        cmd = ["tar","-C", out_dir,
           "-zvxf", in_file]
        p = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=False)
        out, err = p.communicate()
        print("!Error:", err, '! Done:',out_dir)
    


# ## For ISP's Pcap
# parallel by function name

# In[10]:


# %%time
in_file_paths = []
out_dir_paths = []
days = ['2020_01_20','2020_01_21'] #指定日期，清空掉就是全部日子
isps = ['中華電信','中嘉寬頻','亞太電信','凱擘','台固媒體','台灣之星','台灣固網','台灣基礎開發','台灣大哥大',
       '台灣碩網','遠傳電信']
# isps = ['台灣固網','台固媒體']
for date in tqdm(all_dates):
    if date not in days:
        continue
    pcap_path = tgz_dir + date + '/'
    isp_names = next(os.walk(pcap_path))[1]
    take_isps = []
    for isp in isp_names:
        if isp in isps:
            take_isps.append(isp)
    for isp in take_isps:
        file_names = next(os.walk(pcap_path+isp))[2]
        file_names = list(filter(lambda f: f.endswith(".tar.gz"), file_names))
        if len(file_names)>1:
            print('WARNING: more than 1 pcap tgz file in',pcap_path+isp+'/') #可能分part
        for file_name in file_names:
            pcap_path_ = pcap_path+isp+'/'+file_name
            output_path = decompress_dir+date+'/'+isp+'/'+file_name.replace('.tar.gz','_dir')+'/'
            in_file_paths.append(pcap_path_)
            out_dir_paths.append(output_path)

assert len(in_file_paths) == len(out_dir_paths)
assert in_file_paths[0].split('/')[-3] == out_dir_paths[0].split('/')[-4]
assert in_file_paths[-1].split('/')[-2] == out_dir_paths[-1].split('/')[-3]
len(in_file_paths)


# In[11]:


get_ipython().run_cell_magic('time', '', 'load_start = time.time()\npool_result = []\npool = Pool(processes=3) #processes=21\nfor path_in,dir_out in zip(in_file_paths,out_dir_paths):\n    r = pool.apply_async(parallel_untar,args=(path_in,dir_out))\n    pool_result.append(r)\npool.close()\npool.join()\nfor r in pool_result:\n    print(\'return:\',r.get())\nload_end = time.time() - load_start\nprint("Decompress Time:", \'{:02f}:{:02f}:{:02f}\'.format(load_end // 3600, (load_end % 3600 // 60), load_end % 60))')


# ## For ISPs' honeypot

# In[22]:


paths = []
days = ['2020-01-09','2020-01-10','2020-01-11'] #指定日期，清空掉就是全部日子
for name in tqdm(company_names):
    if name != '中華電信': #指定電信公司，註解掉就是全部
        continue
#     print('=== Running:',name,'===')
    hp_path = root_dir + name + '/honeypot/'
    date_dir_names = next(os.walk(hp_path))[1]
    if days != []:
        temp = []
        for date in date_dir_names:
            for day in days:
                if day == date:
                    temp.append(date)
        date_dir_names = temp
    else:
        pass
    for date in date_dir_names:
        hp_date_path = hp_path + date +'/'
        hp_names_dir = next(os.walk(hp_date_path))[1]
        for name in hp_names_dir:
            file_names = next(os.walk(hp_date_path+name+'/'))[2]
            file_names = list(filter(lambda f: f.endswith(".tar.gz"), file_names))
            new_dir_names = [x.replace('.tar.gz','_dir') for x in file_names]
            for dir_name in new_dir_names:
                path = hp_date_path+name+'/'+dir_name
                os.makedirs(path, exist_ok=True)
                paths.append(path)
        
paths


# In[23]:


get_ipython().run_cell_magic('time', '', "pool_result = []\npool = Pool() #processes=21\nfor path in paths:\n    r = pool.apply_async(parallel_untar,(path,))\n    pool_result.append(r)\npool.close()\npool.join()\nfor r in pool_result:\n    print('return:',r)")

