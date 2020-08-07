#!/usr/bin/env python
# coding: utf-8

# In[71]:


# Imports
import pandas as pd
import glob
import subprocess
import socket
import re
import csv
import sys
import math
import numpy as np
from joblib import dump, load
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from statistics import stdev, mean


# In[72]:


#UTIL to process pcap files
TIME_WINDOW = 3600 # 1 hr in sec
TSHARK_FIELDS = " -e _ws.col.Protocol -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e _ws.col.Time -e _ws.col.Source -e _ws.col.Destination -e _ws.col.Length -e tcp.len -e udp.length -e tcp"

# fields retrieved from pcap
fields = '''
protocol
srcport
dstport

time

source
destination

totallen
datalen

istcp

src_dst
sip_dip
'''.split()

fields_dict = dict()

i = 0
for field in fields: 
    fields_dict[field]=i
    i+=1


# In[73]:


# Process file function
def parse_cap(file_name):
    command= "tshark -r "+file_name+" -Y "+"'ip.version==4&&(tcp||udp)&&(!dns)'"+         " -T fields " + TSHARK_FIELDS + " -E separator='|' 2>/dev/null"
            
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    
    outs =[]
    
    i=0
    
    while True:
        print(f'\rPackets Processed: {i}',end = '')
        i+=1
        
        line = p.stdout.readline()
        
        if not line:
            break
        
        line = line.decode('utf-8').strip()
        
        splits = line.split('|')
        
        l = []

        try:
            # append protocol
            l.append(splits[0].strip())

            # if TCP, append ports
            if splits[11].strip()!='':
                l.append(int(splits[1].strip()))
                l.append(int(splits[2].strip()))
            else:
                l.append(int(splits[3].strip()))
                l.append(int(splits[4].strip()))

            # append time
            l.append(float(splits[5].strip()))

            # append src, dst ip
            l.extend(splits[6:8])

            # append totallen
            l.append(int(splits[8].strip()))

            # if TCP, append datalen and istcp
            if splits[11].strip()!='':
                try:
                    l.append(int(splits[9].strip()))
                except:
                    l.append(0)
                l.append(1)
            else:
                try:
                    l.append(int(splits[10].strip()))
                except:
                    l.append(0)
                l.append(0)

            # append src+dst for grouping, and sip+dip
            l.append(min(splits[6],splits[7])+'__'+max(splits[6],splits[7]))
            
            l.append(str(min(l[fields_dict['srcport']], l[fields_dict['dstport']]))+'__'+str(max(l[fields_dict['srcport']], l[fields_dict['dstport']])))

            index = int(int(l[fields_dict['time']])/TIME_WINDOW)

            if index >= len(outs):
                out = [l]
                outs.append(out)
            else:
                outs[index].append(l)

        except Exception as e:
            print("ER1", e, line, splits)

    print('\r')
    
    try:
        dfs = []
        for out in outs:
            df = pd.DataFrame(out, columns = fields)
            dfs.append(df)
        return dfs
    except Exception as e:
        print("ER2", e, outs, fields)
        return pd.DataFrame()


# In[74]:


# Feature Extraction Function (returns list of list of 23 (18 used in classification) faetures)
def extr_feats(df, t_bool):
  
    groups = df.groupby(['src_dst','protocol','sip_dip'])
    
    features = []

    for key in groups.groups:
        
        f = [0 for x in range (0,23)]
        
        f[0] = 0.0
        
        f[6] = 9223372036854775807
        f[14] = f[16] = 0.0
        f[9] = f[15] = f[17] = 3601.0
        
        time_last = -1
        time_last_f = -1
        time_last_b = -1
        
        f_count = 0
        b_count = 0
        
        tmp_src = key[0].split('__')[0]
        tmp_dst = key[0].split('__')[1]
        
        
        ####### FLOW_DETAILS_NOT_USED_IN_CLASSIFICATION (just used in output of detection model)#################
        f[18] = tmp_src
        f[19] = tmp_dst
        f[20] = key[2].split('__')[0]
        f[21] = key[2].split('__')[1]
        f[22] = key[1]
        ##########################################################################################################
        
        
        i = 1        
        
        time_last = -1

        for _, row in groups.get_group(key).iterrows():
            
            if(time_last == -1):
                time_last = row['time']
            
            t_diff = row['time']-time_last
            time_last = row['time']
            
            
            # f1 (left, divide by nos)
            f[0] += t_diff
            
            # f2, f3, f4, f5
            if row['source'] == tmp_src:                
                f[1]+=1
                
                f[3]+=row['datalen']
            else:
                f[2]+=1
                
                f[4]+=row['datalen']
                
                
            # f6
            f[5]+=row['totallen']
            
            # f7, f8
            f[6] = min(f[6], row['totallen'])
            f[7] = max(f[7], row['totallen'])
            
            # f9, f10
            f[8] = max(f[8], t_diff)
            
            if(t_diff!=0.0):
                f[9] = min(f[9], t_diff)
            
            # f11
            f[10] += t_diff
            
            # (f13, f14 (divide at end)), f15, f16, f17, f18
            if row['source'] == tmp_src:
                if(time_last_f == -1):
                    time_last_f = row['time']
                
                t_diff_f = row['time']-time_last_f 
                
                f[12] += t_diff_f
                f_count+=1
                
                f[14] = max(f[14], t_diff_f)
                if t_diff_f != 0.0:
                    f[15] = min(f[15], t_diff_f)
            else:
                if(time_last_b == -1):
                    time_last_b = row['time']
                    
                t_diff_b = row['time']-time_last_b 
                
                f[13] += t_diff_b
                b_count+=1
                
                f[16] = max(f[16], t_diff_b)
                if t_diff_b != 0.0:
                    f[17] = min(f[17], t_diff_b)
            
            i+=1
            
        # FILTERING for flows with bidirectional packets and time window > 1/4 of the pcap field capturing window i.e. 1/4 * (3600) secs
        if( i<=2 or f_count<=1 or b_count<=1 or ((not t_bool) and f[10] < 900)):
            # dont append these features
            continue
        
        
        # f1, f12
        f[0] = f[0]/(i-2)     # len(groups.get_group(key))-1
        f[11] = f[10]/(i-2)   # len(groups.get_group(key))-1
        
        #f13, f14 
        if f_count > 0:
            f[12] /= f_count 
        if b_count > 0:
            f[13] /= b_count 
        
        # 3601.0 marks unavailability of feature
        # WILL NEVER OCCUR (as such cases already filtered)
        for i in [8,9,12,13,14,15,16,17]:
            if f[i]==0 or f[i] == 0.0:
                f[i]=3601.0
        

        features.append(f)
        
    return features


# In[75]:


# Get features util
def get_feats(dfs, t_bool):
    feats = []
    for df in dfs:
        fs = extr_feats(df, t_bool)
        try:
            if fs and len(fs)>0:
                feats.extend(fs)
        except Exception as e:
            print("Caught exception while adding feats:", e)
    return pd.DataFrame(feats, columns = '''F1,F2,F3,F4,F5,F6,F7,F8,F9,F10,F11,F12,F13,F14,F15,F16,F17,F18,TMP_SRC_IP,TMP_DST_IP,SRC_P,DST_P,PROTO'''.split(','))


# In[82]:


# Returns dataframe with all features for "file"
def parse_and_get_feats(file, t_bool = False):
    print("PARSING: "+file)
    dfs = parse_cap(file)
    try:
        if dfs:
            print("EXTRACTING FEATURES...")
            feats = get_feats(dfs, t_bool)
            print('COMPLETED!')
            return feats, feats.shape[0]          
        else:
            print("No fields returned for this file.")
    except Exception as e:
        print("Caught exception while processing the file:", e)

    return pd.DataFrame(), 0


# In[77]:


# Classify into benign or mal
def botnet_inference(df):
    # df is of the format [rows, 23] which was originally read from csv
    df_np = df.to_numpy()[:, :-5]
    
    scaler = load('./saved_models/botnet_classifiy_scaler.joblib')
    df_np = scaler.transform(df_np)
    
    classifier = load('./saved_models/botnet_classifier.joblib')
    predictions = classifier.predict(df_np)
    
    df['label'] = predictions
    # label 1 denotes -> flow is botnet traffic
    # label 0 denotes -> flow is normal traffic
    
    return df


# In[78]:


# Classify into 1 2 1-2 for botnet
def flow_direction_inference(df):
    # df is of the format [rows, 24] and contains only botnet labelled flows
    # df here is the output of botnet_inference
    df_np = df.to_numpy()[:, :-6]
    flow_columns = ['TMP_SRC_IP', 'TMP_DST_IP']
    output = df[flow_columns]
    
    scaler = load('./saved_models/src_dst_classify_scaler.joblib')
    df_np = scaler.transform(df_np)
    
    # remove unnecessary features
    feat_keep_idx = [3, 4, 15, 17]
    df_np = df_np[:, feat_keep_idx]
    
    classifier = load('./saved_models/src_dst_classifier.joblib')
    predictions = classifier.predict(df_np)
    
    output['label'] = predictions
    # label 0 denotes -> src_ip = botnet
    # label 1 denotes -> dst_ip = botnet
    # label 2 denotes -> both ips = botnet
    
    return output


# In[79]:


# Use Statistics to weed out any outliers in the inference
def clean_inference(df, number_of_flows):
    dictionary = dict()
    
    for _,o in df.iterrows():
        ip1 = o['TMP_SRC_IP']
        ip2 = o['TMP_DST_IP']
        
        if o['label']=='0' or o['label']==0:
            if ip1 in dictionary:
                dictionary[ip1] += 1
            else: 
                dictionary[ip1] = 1
        elif o['label']=='1' or o['label']==1:
            if ip2 in dictionary:
                dictionary[ip2] += 1
            else: 
                dictionary[ip2] = 1
        elif o['label']=='2' or o['label']==2:
            if ip1 in dictionary:
                dictionary[ip1] += 1
            else: 
                dictionary[ip1] = 1
            if ip2 in dictionary:
                dictionary[ip2] += 1
            else: 
                dictionary[ip2] = 1
    
    flow_bot = dict()
    flow_ips = list()
    for ip in dictionary: 
        percentage = (dictionary[ip]/number_of_flows)*100
        if percentage > 0.5:
            flow_bot[ip] = percentage
            flow_ips.append(ip)
    return flow_bot, flow_ips


# In[83]:


# Find final solution, save to CSV

# Input the pcap filename here
if len(sys.argv) == 1:
    print('Please add the pcap file path as the first argument')
    exit()

PCAP = sys.argv[1]

print('Parsing and extracting features...', '\n') 
features, number_of_flows = parse_and_get_feats(PCAP)

if number_of_flows == 0:
    features, number_of_flows = parse_and_get_feats(PCAP, True)


if number_of_flows == 0:
    print('Too less packet data, results inconclusive!')
    with open('output.txt', 'w') as f: 
        f.write('Too less packet data, results inconclusive!')
    print('Saving to output.txt')
    print('exiting')
else:
    print('Classifying as Botnet/Benign', '\n')
    flow_inference_df = botnet_inference(features)

    botnet_df = flow_inference_df[flow_inference_df['label']==1]

    # Stop if no botnet flows found
    if botnet_df.shape[0] == 0: 
        print('No Botnet hosts found!')
        with open('output.txt', 'w') as f: 
            f.write('No Botnet hosts found!')
        print('Saving to output.txt')
        print('exiting')
    else:

        print('Finding the Botnet IPs in the Botnet', '\n')
        host_df = flow_direction_inference(botnet_df)

        print('Cleaning the output', '\n')
        clean_dict, clean_list = clean_inference(host_df, number_of_flows)

        if len(clean_list) == 0: 
            print('No Botnet hosts found!')
            with open('output.txt', 'w') as f: 
                f.write('No Botnet hosts found!')
            print('Saving to output.txt')
            print('exiting')
        else:
            print('List of Botnet Hosts: ', '\n')
            host_s = ''
            for host in clean_list: 
                print (host)
                host_s = host_s+host+'\n'
                with open('output.txt', 'w') as f: 
                    f.write("Bot (infected) IPs:\n")
                    f.write(host_s)

            print('Saved to output.txt')

