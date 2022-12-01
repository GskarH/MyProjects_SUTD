import pandas as pd
import numpy as np
import sys
from functools import reduce
import socket
import struct
import ipaddress
import time
import shutil
import subprocess

def predictedResult(TCP, FTR, FTD, IPP, IPL, IPF):
    try:
        if(TCP>21):
            return 1
        else:
            if(FTR>49.02):
                if(IPP>6):
                    if(IPL>71):
                        if(IPL>75):
                            if(IPL>83):
                                if(IPF>0):
                                    if(IPL>100):
                                        if(FTR>538.8):
                                            return 1
                                        else:
                                            return 0
                                    else:
                                        return 1
                                else:
                                    return 1
                            else:
                                if(FTD>0.103725):
                                    return 1
                                else:
                                    return 0
                        else:
                            return 1
                    else:
                        if(IPL>64):
                            return 0
                        else:
                            return 1
                else:
                    if(IPL>144):
                        if(IPP>1):
                            return 0
                        else:
                            return 1
                    else:
                        if(FTR>624.21):
                            if(IPL>40):
                                return 0
                            else:
                                return 1
                        else:
                            return 0
            else:
                if(FTR>44.9):
                    return 1
                else:
                    if(IPP>6):
                        return 1
                    else:
                        return 0
    except Exception as e1:
        print(str(e1))
        return 2

cnt_benign = cnt_malicious = r1 = 0
a=1
while(a>0):
    try:
        shutil.copyfile("live.csv", "live1.csv")
        df = pd.read_csv("live1.csv", lineterminator='\n')
        df1 = df.replace(np.nan, 0)
        df1.columns = [c.replace('.', '_') for c in df1.columns]
        r2 = len(df1)
        if(r2<r1):
            print("Waiting for new packets to be loaded in CSV file...")
            time.sleep(10)
            print("Reloading CSV file...")
        else:
            print("New data found...\nLive detection running...")
            for i in range(r1,r2):
                result = 0
                result = predictedResult(df1.tcp_stream[i], df1.frame_time_relative[i], df1.frame_time_delta[i], df1.ip_proto[i], df1.ip_len[i], df1.ip_flags_df[i])
                if(result == 1):
                    cnt_malicious=cnt_malicious+1
                    print('\033[1m' + "*****************NEW NETWORK ANOMALY DETECTED!!!*****************" + '\033[0m')
                elif(result == 0):
                    cnt_benign=cnt_benign+1
                    print("Benign")
                else:
                    print("An exception occurred..")
                    continue
            r1 = r2+1
            print("\n\nBenign: ", cnt_benign,"    Malicious: ",cnt_malicious, "    at    ",time.strftime("%H: %M: %S", time.localtime(time.time())),"\n\n")
    except Exception as e:

        continue
