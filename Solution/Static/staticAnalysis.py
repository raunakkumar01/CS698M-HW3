
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

features = ['Machine', 'SizeOfOptionalHeader','Characteristics', 'MajorLinkerVersion', 'MinorLinkerVersion','SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData','AddressOfEntryPoint', 'BaseOfCode', 'BaseOfData', 'ImageBase','SectionAlignment', 'FileAlignment', 'MajorOperatingSystemVersion','MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion','MajorSubsystemVersion', 'MinorSubsystemVersion', 'SizeOfImage','SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics','SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve','SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes']
api = ['imagelist', 'getprocaddress', 'loadlibrarya', 'writefile', 'closehandle', 'exitprocess', 'getlasterror', 'getmodulehandlea', 'getcommandlinea', 'multibytetowidechar', 'sleep', 'readfile', 'getmodulefilenamea', 'getmodulehandlew', 'getcurrentprocess', 'getstdhandle', 'widechartomultibyte', 'raiseexception', 'rtlunwind', 'getmodulefilenamew', 'setendoffile', 'getacp', 'unhandledexceptionfilter', 'getfiletype', 'getcurrentthreadid', 'setlasterror', 'heapalloc', 'heapfree', 'entercriticalsection', 'terminateprocess', 'leavecriticalsection', 'getcpinfo', 'getstringtypew', 'deletecriticalsection', 'getoemcp', 'queryperformancecounter', 'lcmapstringw', 'heaprealloc', 'tlsgetvalue', 'tlssetvalue', 'virtualalloc', 'getenvironmentstringsw', 'freeenvironmentstringsw', 'setunhandledexceptionfilter', 'getcurrentprocessid', 'createfilew', 'getsystemtimeasfiletime', 'getprocessheap', 'loadlibraryexw', 'setstdhandle', 'flushfilebuffers', 'loadlibraryw', 'tlsalloc', 'initializecriticalsectionandspincount', 'heapsize', 'tlsfree', 'getstartupinfow', 'regclosekey', 'isvalidcodepage', 'getconsolemode', 'writeconsolew', 'isdebuggerpresent', 'virtualfree', 'isprocessorfeaturepresent', 'getconsolecp', 'decodepointer', 'setfilepointerex', 'getmodulehandleexw', 'encodepointer', 'outputdebugstringw', 'arefileapisansi', 'readconsolew', 'setfilepointer', 'messageboxa', 'freelibrary', 'createfilea', 'getdc', 'getfilesize', 'gettickcount', 'waitforsingleobject', 'findclose', 'getexitcodeprocess', 'regqueryvalueexa', 'destroywindow', 'getversion', 'deletefilea', 'regopenkeyexa', 'wsprintfa', 'getcommandlinew', 'seterrormode', 'lstrlena', 'cotaskmemfree', 'showwindow', 'createthread', 'getsystemmetrics', 'globalalloc', 'createprocessa', 'getfileattributesa', 'localfree', 'dispatchmessagea', 'sendmessagea', 'getdlgitem', 'createdirectorya', 'exitwindowsex', 'getstartupinfoa', 'shellexecutea', 'virtualquery', 'globalfree', 'settimer', 'getwindowsdirectorya', 'enddialog', 'getwindowrect', 'createwindowexa', 'postquitmessage', 'findfirstfilea', 'setwindowpos', 'setfiletime', 'deleteobject', 'peekmessagea', 'enablewindow']

def hex(s):
	try:
		val = int(s,16)
		return val
	except ValueError:
		return 0

wb = Workbook()
sheet1 = wb.add_sheet('Sheet 1') 
sheet1.write(0,0,'Name')
sheet1.write(0,1,'PredictedLabel')
for i in range(len(features)):
	sheet1.write(0,i+2,features[i])
for i in range(len(api)):
	sheet1.write(0,len(features)+i+2,api[i])

###########################################Malware########################################333

file_list = []

def get_files(path):
	dir_entries = os.listdir(path)
	for entry in dir_entries:
		sub_dir = os.listdir(path+entry+'/')
		if(len(sub_dir)>0):
			for file in sub_dir:
				file_list.append(path+entry+'/'+file+'/Structure_Info.txt')

get_files('Malware/')
for file in range(len(file_list)):
	with open(file_list[file],"rt",encoding='latin-1') as f:
		print('M'+str(file))
		sheet1.write(file+1,0,f.name)
		sheet1.write(file+1,1,'M')
		fet_m = features.copy()
		api_m = api.copy()
		#############################FOR header features############################
		for line in f:
			if len(fet_m) > 0:
				for pat in range(len(fet_m)):
					pattern = re.compile(fet_m[pat])
					if pattern.search(line) != None:      # If a match is found 
						data = line.rstrip('\n').split()
						val = 0
						val+= hex(data[3])
						sheet1.write(file+1,features.index(fet_m[pat])+2,val)#int(data[3], 16))
						fet_m.remove(fet_m[pat])
						break

		#########################For API ###########################################
			if len(api_m) > 0:
				for pat in range(len(api_m)):
					pattern = re.compile(api_m[pat],re.IGNORECASE)
					if pattern.search(line) != None:      # If a match is found 
						val = 1
						sheet1.write(file+1,len(features)+api.index(api_m[pat])+2,val)#int(data[3], 16))
						api_m.remove(api_m[pat])
						break
			
		for pat in range(len(api_m)):
			val = 0
			sheet1.write(file+1,len(features)+api.index(api_m[pat])+2,val)#int(data[3], 16))
#############################################Bnign###################################################
x = len(file_list)
def get_files_B(path):
	dir_entries = os.listdir(path)
	for entry in dir_entries:
		file_list.append(path+entry+'/Structure_Info.txt')

file_list = []
get_files_B('Benign/')
for file in range(len(file_list)):
	with open(file_list[file],"rt",encoding='latin-1') as f:
		print(file)
		sheet1.write(x+file+1,0,f.name)
		sheet1.write(x+file+1,1,'B')
		fet_m = features.copy()
		api_m = api.copy()
		#############################FOR header features############################
		for line in f:
			if len(fet_m) > 0:
				for pat in range(len(fet_m)):
					pattern = re.compile(fet_m[pat])
					if pattern.search(line) != None:      # If a match is found 
						data = line.rstrip('\n').split()
						val = 0
						val+= hex(data[3])
						sheet1.write(x+file+1,features.index(fet_m[pat])+2,val)#int(data[3], 16))
						fet_m.remove(fet_m[pat])
						break

		#########################For API ###########################################
			if len(api_m) > 0:
				for pat in range(len(api_m)):
					pattern = re.compile(api_m[pat],re.IGNORECASE)
					if pattern.search(line) != None:      # If a match is found 
						val = 1
						sheet1.write(x+file+1,len(features)+api.index(api_m[pat])+2,val)#int(data[3], 16))
						api_m.remove(api_m[pat])
						break
			
		for pat in range(len(api_m)):
			val = 0
			sheet1.write(x+file+1,len(features)+api.index(api_m[pat])+2,val)#int(data[3], 16))



# for file in range(len(file_list)):
# 	with open(file_list[file],"rt",encoding='latin-1') as f:
# 		sheet1.write(file+1,0,f.name)
# 	sheet1.write(file+1,1,'M')
# 	#############################FOR header features############################
# 	for pat in range(len(features)):
# 		with open(file_list[file],"rt",encoding='latin-1') as f:
# 			for line in f:
# 				pattern = re.compile(features[pat])
# 				if pattern.search(line) != None:      # If a match is found 
# 					data = line.rstrip('\n').split()
# 					val = 0
# 					val+= int(data[3], 16)
# 					sheet1.write(file+1,pat+2,val)#int(data[3], 16))
# 					break
# 	#########################For API ###########################################
# 	for pat in range(len(api)):
# 		with open(file_list[file],"rt",encoding='latin-1') as f:
# 			for line in f:
# 				pattern = re.compile(api[pat],re.IGNORECASE)
# 				if pattern.search(line) != None:      # If a match is found 
# 					val = 1
# 					sheet1.write(file+1,len(features)+pat+2,val)#int(data[3], 16))
# 					break
			
# #############################################Bnign###################################################
# x = len(file_list)
# def get_files_B(path):
# 	dir_entries = os.listdir(path)
# 	for entry in dir_entries:
# 		file_list.append(path+entry+'/Structure_Info.txt')

# file_list = []
# get_files_B('Benign/')
# for file in range(len(file_list)):
# 	with open(file_list[file],"rt",encoding='latin-1') as f:
# 		sheet1.write(x+file+1,0,f.name)
# 	sheet1.write(x+file+1,1,'B')
# 	#############################FOR header features############################
# 	for pat in range(len(features)):
# 		with open(file_list[file],"rt",encoding='latin-1') as f:
# 			for line in f:
# 				pattern = re.compile(features[pat])
# 				if pattern.search(line) != None:      # If a match is found 
# 					data = line.rstrip('\n').split()
# 					val = 0
# 					val+= int(data[3], 16)
# 					sheet1.write(x+file+1,pat+2,val)#int(data[3], 16))
# 					break
# 	#########################For API ###########################################
# 	for pat in range(len(api)):
# 		val = 0
# 		with open(file_list[file],"rt",encoding='latin-1') as f:
# 			for line in f:
# 				pattern = re.compile(api[pat],re.IGNORECASE)
# 				if pattern.search(line) != None:      # If a match is found 
# 					val = 1
# 					break
# 		sheet1.write(x+file+1,len(features)+pat+2,val)#int(data[3], 16))
wb.save('StaticAnalysis.xlt')