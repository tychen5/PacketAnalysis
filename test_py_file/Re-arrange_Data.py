#!/usr/bin/env python
# coding: utf-8

# In[1]:


import os,sys
import shutil,glob
import pickle
import path
from tqdm import tqdm
import hashlib


# In[2]:


rearrange_dir = '../../RAID6/original_tmp_data/0223-0307/'


# In[3]:


all_files = glob.glob(rearrange_dir+'**/*.tar.gz', recursive=True)
all_files


# .split('/') :
# * 4=>pcap/hp
# * 3=>ISP (轉換)
# * 5=>date (注意格式)
# * 6=>fileName
# ***
# #### 最原本.tar.gz/.json TTC所給之原始檔案目前位於RAID5目錄下
# * pcap 
#     * date
#         * ISP
#             * fileName
# * honeypot 
#     * date
#         * type
#             * ISP or mongoDB
#                 * fileName
# 
# #### 經解壓縮、加工處理後等大size個別資料目前位於 data_hdd4t目錄下
# * pcap_process
#     * date
#         * ISP
#             * fileName
# * honeypot_process
#     * date
#         * type
#             * ISP or mongoDB
#                 * fileName
# 
# #### spark dataframe、pickle等經過整合或小size資料目前位於spark_data目錄下
# * pcap_inter
#     * date
#         * ISP
#             * fileName
# * honeypot_inter
#     * date
#         * type
#             * ISP or mongoDB
#                 * fileName

# In[7]:


def aliase_convert(s):
    '''
    dictionary baesd conversion
    '''
    if s == '台哥大':
        return '台灣大哥大'
    elif s == '台基開發':
        return '台灣基礎開發'
    elif s == '亞太':
        return '亞太電信'
    elif s == '遠傳':
        return '遠傳電信'
    else:
        return s


# In[9]:


idx = -1
print(all_files[idx].split('/'))
len(all_files[idx].split('/'))
#10=>hp
#9=>pcap


# In[8]:


for i,path in (enumerate(all_files)):
    if 'mongo' in path:
        print(i) #不應該要有印出東西
        break


# In[10]:


for path in tqdm(all_files):
    path_li = path.split('/')
    if path_li[3] in ['pcap','honeypot','metadata']: #如果是已經分好在RAID5的就不要動 #需要改
        continue
    if len(path_li) == 9: #pcap #需要改
        date_dir = path_li[-2] #日期須修改
        date_dir = date_dir.replace('-','_')
        assert len(date_dir.split('_')) == 3
        isp_dir = path_li[-4] #isp名稱位置 #需要改
        isp_dir = aliase_convert(isp_dir)
        fileName = path_li[-1]
        assert 'pcap' in fileName
        assert date_dir.split('_')[-1] in fileName
        assert '.tar.gz' in fileName
        save_dir = '../../RAID5/'+'pcap/'+date_dir+'/'+isp_dir #要儲存的位置 #需要改
        if not os.path.exists(save_dir):
            os.makedirs(save_dir,exist_ok=True)
        try:
            shutil.move(path,save_dir+'/')
        except :
            print(path)
            ori = hashlib.md5(open(path,'rb').read()).hexdigest()
            dest =  hashlib.md5(open('../../RAID5/'+'pcap/'+date_dir+'/'+isp_dir+'/'+fileName,'rb').read()).hexdigest()
            if ori == dest:
                os.remove(path)
            else:
                print('_2 was created')                
                shutil.move(path,save_dir+'/'+fileName+'_2')
    elif len(path_li) == 10: #hp #長度需要改
        date_dir = path_li[-2] #日期須檢查
        date_dir = date_dir.replace('-','_')
        assert len(date_dir.split('_')) == 3
        type_dir = path_li[-3] #hp的type #需要改
        assert type_dir in ['amun', 'cowrie', 'dionaea',  'glastopf']
        isp_dir = path_li[-5] #isp名稱位置 #需要改
        isp_dir = aliase_convert(isp_dir)
        fileName = path_li[-1]
        assert type_dir in fileName
        assert date_dir.split('_')[-1] in fileName
        assert '.tar.gz' in fileName
        save_dir = '../../RAID5/'+'honeypot/'+date_dir+'/'+type_dir+'/'+isp_dir#要儲存的位置 #需要改
        if not os.path.exists(save_dir):
            os.makedirs(save_dir,exist_ok=True)        
        try:
            shutil.move(path,save_dir+'/')
        except : #重複一模一樣的檔名
            print(path)
            ori = hashlib.md5(open(path,'rb').read()).hexdigest()
            dest =  hashlib.md5(open(save_dir+'/'+fileName,'rb').read()).hexdigest()
            if ori == dest: #真的一模一樣舊移除舊的
                os.remove(path)
            else: #不一樣舊都保留到新的位置去
                print('_2 was created')
                shutil.move(path,save_dir+'/'+fileName+'_2')
    else:
        print("WARNING!!Assertion failed, not pcap nor hp. :",path)
            


# In[11]:


def recursive_delete_if_empty(path):
    """Recursively delete empty directories; return True
    if everything was deleted."""

    if not os.path.isdir(path):
        # If you also want to delete some files like desktop.ini, check
        # for that here, and return True if you delete them.
        return False

    # Note that the list comprehension here is necessary, a
    # generator expression would shortcut and we don't want that!
    if all([recursive_delete_if_empty(os.path.join(path, filename))
            for filename in os.listdir(path)]):
        # Either there was nothing here or it was all deleted
        os.rmdir(path)
        return True
    else:
        return False


# In[12]:


one = recursive_delete_if_empty(rearrange_dir)
# two = recursive_delete_if_empty(rearrange_dir+'0126_0208')
# three = recursive_delete_if_empty(rearrange_dir+'1229_0112')
print(one)#,two,three)

