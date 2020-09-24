import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import os
# Writing to an excel  
# sheet using Python 
import xlwt 
import re
import csv
from xlwt import Workbook

features = ['Machine', 'SizeOfOptionalHeader', 'Characteristics', 'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode', 'BaseOfData', 'ImageBase', 'SectionAlignment', 'FileAlignment', 'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion', 'MinorSubsystemVersion', 'SizeOfImage', 'SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve', 'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes', 'SectionsNb', 'SectionsMeanEntropy', 'SectionsMinEntropy', 'SectionsMaxEntropy', 'SectionsMeanRawsize', 'SectionsMinRawsize', 'SectionMaxRawsize', 'SectionsMeanVirtualsize', 'SectionsMinVirtualsize', 'SectionMaxVirtualsize', 'ImportsNbDLL', 'ImportsNb', 'ImportsNbOrdinal', 'ExportNb', 'ResourcesNb', 'ResourcesMeanEntropy', 'ResourcesMinEntropy', 'ResourcesMaxEntropy', 'ResourcesMeanSize', 'ResourcesMinSize', 'ResourcesMaxSize', 'LoadConfigurationSize', 'VersionInformationSize']
# findSize = ['SizeOfOptionalHeader','SizeOfStackReserve','SizeOfStackCommit','SizeOfHeapReserve','SizeOfHeapCommit','SizeOfCode','SizeOfInitializedData','SizeOfUninitializedData','SizeOfImage','SizeOfHeaders']
# peSize = ['Misc_VirtualSize','SizeOfRawData','NumberOfRelocations','NumberOfLinenumbers']#Data for each PE header file *4
# print(features)
###########################################Benign########################################333
api_all_b = []
file_list = []
def get_files_B(path):
	dir_entries = os.listdir(path)
	for file in dir_entries:
		file_list.append(path+file+'/Structure_Info.txt')

get_files_B('Benign/')

ben = []

for file in range(3):#len(file_list)):
    with open(file_list[file],"rt",encoding='latin-1') as f:
        all_data = f.read()
        data = re.split(r'\-+[a-zA-Z _]+\-+',all_data)#f.read())
        #data 1:DOS_HEADER 3:FILE_HEADER 4:OPTIONAL_HEADER 5:PE Sections 8:Imported symbols
        feature = set(features)
        ben_dic ={}
        ######################For API##############################
        api = {}#dictionary for each api corresponding file
        api_b = ""
        val = re.findall(r'[a-zA-Z0-9.]*.dll[a-zA-Z.]*',all_data)
        for v in val:
            if(len(v.split("."))>2):
                api_b = " ".join([api_b.strip(),(v.split(".")[2].strip())])
                if v.split(".")[2] in api:
                    api[v.split(".")[2]] += 1
                else:
                    api[v.split(".")[2]]  = 1
#         api_m.append(api) 
        ######################For PE###############################
#         data_pe = re.split(r'IMAGE_SECTION_HEADER',data[5])
#         for e in range(1,len(data_pe)):#for 5 blocks 6 elements created therefore start from index 1
#             print(data_pe[e]+"\n$$$AA$")
        ######################For All The Features Data###########
#         print(len(feature))
        for e in features:
            rx = "[0-9A-Zx]+\s+[0-9A-Zx]+\s+"+e+":\s+[0-9A-Zx]+"
            pat = re.compile(e,re.IGNORECASE)
            if pat.search(all_data):
                line = re.findall(rx,all_data,re.S)
#                 feature.remove(e)
                val = 0
                val+= int((line[0].split())[3], 16)
                ben_dic[e] = val
        new_dic = {}
        new_dic['Name'] = f.name
        new_dic['PredictedLabel'] = 'B'
        new_dic.update(ben_dic)
#         new_dic.update(api)
        new_dic['APIValue'] = api_b
        
        
        ben.append(new_dic)
        if api_b and api_b.strip():
            api_all_b.append(api_b.strip())

df_ben_fet = pd.DataFrame(ben)
df_api_ben = pd.DataFrame(api_all_b)
# print(df_api_mal)
print(df_ben_fet)
df_ben_fet.to_csv(r'file_ben_feat_1.csv',index=False)
df_api_ben.to_csv(r'file_ben_api_1.csv',index=False)
