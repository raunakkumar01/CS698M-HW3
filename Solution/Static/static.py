# -*- coding: utf-8 -*-
import numpy as np
import pandas as pd
import joblib
import sys
from sklearn.metrics import confusion_matrix, accuracy_score, f1_score
import pathlib
import re
# Extract data

features = ['Machine', 'SizeOfOptionalHeader','Characteristics', 'MajorLinkerVersion', 'MinorLinkerVersion','SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData','AddressOfEntryPoint', 'BaseOfCode', 'BaseOfData', 'ImageBase','SectionAlignment', 'FileAlignment', 'MajorOperatingSystemVersion','MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion','MajorSubsystemVersion', 'MinorSubsystemVersion', 'SizeOfImage','SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics','SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve','SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes']
api = ['imagelist', 'getprocaddress', 'loadlibrarya', 'writefile', 'closehandle', 'exitprocess', 'getlasterror', 'getmodulehandlea', 'getcommandlinea', 'multibytetowidechar', 'sleep', 'readfile', 'getmodulefilenamea', 'getmodulehandlew', 'getcurrentprocess', 'getstdhandle', 'widechartomultibyte', 'raiseexception', 'rtlunwind', 'getmodulefilenamew', 'setendoffile', 'getacp', 'unhandledexceptionfilter', 'getfiletype', 'getcurrentthreadid', 'setlasterror', 'heapalloc', 'heapfree', 'entercriticalsection', 'terminateprocess', 'leavecriticalsection', 'getcpinfo', 'getstringtypew', 'deletecriticalsection', 'getoemcp', 'queryperformancecounter', 'lcmapstringw', 'heaprealloc', 'tlsgetvalue', 'tlssetvalue', 'virtualalloc', 'getenvironmentstringsw', 'freeenvironmentstringsw', 'setunhandledexceptionfilter', 'getcurrentprocessid', 'createfilew', 'getsystemtimeasfiletime', 'getprocessheap', 'loadlibraryexw', 'setstdhandle', 'flushfilebuffers', 'loadlibraryw', 'tlsalloc', 'initializecriticalsectionandspincount', 'heapsize', 'tlsfree', 'getstartupinfow', 'regclosekey', 'isvalidcodepage', 'getconsolemode', 'writeconsolew', 'isdebuggerpresent', 'virtualfree', 'isprocessorfeaturepresent', 'getconsolecp', 'decodepointer', 'setfilepointerex', 'getmodulehandleexw', 'encodepointer', 'outputdebugstringw', 'arefileapisansi', 'readconsolew', 'setfilepointer', 'messageboxa', 'freelibrary', 'createfilea', 'getdc', 'getfilesize', 'gettickcount', 'waitforsingleobject', 'findclose', 'getexitcodeprocess', 'regqueryvalueexa', 'destroywindow', 'getversion', 'deletefilea', 'regopenkeyexa', 'wsprintfa', 'getcommandlinew', 'seterrormode', 'lstrlena', 'cotaskmemfree', 'showwindow', 'createthread', 'getsystemmetrics', 'globalalloc', 'createprocessa', 'getfileattributesa', 'localfree', 'dispatchmessagea', 'sendmessagea', 'getdlgitem', 'createdirectorya', 'exitwindowsex', 'getstartupinfoa', 'shellexecutea', 'virtualquery', 'globalfree', 'settimer', 'getwindowsdirectorya', 'enddialog', 'getwindowrect', 'createwindowexa', 'postquitmessage', 'findfirstfilea', 'setwindowpos', 'setfiletime', 'deleteobject', 'peekmessagea', 'enablewindow']

path = pathlib.Path('/home/raunak/COursework/2SEM/CS698m/HW3/Static')

def hex(s):
	try:
		val = int(s,16)
		return val
	except ValueError:
		return 0

def extract():
	##############################Find all the path names#########################
	# path = pathlib.Path('/home/raunak/Downloads/Static_Analysis_RAWDATA')
	file_list = [ f for f in path.glob('**/Structure_Info.txt')]


	fet = []
	###################################Extract the features#############################
	for file in range(len(file_list)):
		with open(file_list[file],"rt",encoding='latin-1') as f:
			dic = {}
			dic['Name'] = f.name
			fet_m = features.copy()
			api_m = api.copy()
			for pat in range(len(fet_m)):
				val = 0
				dic[fet_m[pat]] = val	
			for pat in range(len(api_m)):
				val = 0
				dic[api_m[pat]] = val
			#############################FOR header features############################
			for line in f:
				if len(fet_m) > 0:
					for pat in range(len(fet_m)):
						pattern = re.compile(fet_m[pat])
						if pattern.search(line) != None:      # If a match is found 
							data = line.rstrip('\n').split()
							val = 0
							val+= hex(data[3])
							dic[fet_m[pat]] = val
							fet_m.remove(fet_m[pat])
							break

			#########################For API ###########################################
				if len(api_m) > 0:
					for pat in range(len(api_m)):
						pattern = re.compile(api_m[pat],re.IGNORECASE)
						if pattern.search(line) != None:      # If a match is found 
							val = 1
							dic[api_m[pat]] = val
							api_m.remove(api_m[pat])
							break
			fet.append(dic)
	df_fet = pd.DataFrame(fet)
	# df_fet.to_csv(r'file_test_fet_1.csv',index=False)
	return df_fet

# extract()

################################### Load the data #################################
path = pathlib.Path(input("Enter path :"))
df_fet = extract()#pd.read_csv('file_test_fet_1.csv')
x = np.array(df_fet.iloc[:, 1:152])
nm = np.array(df_fet.iloc[:,0])
x = pd.DataFrame(x).fillna(0)

############################# Load the model################################################3
model_filename = "model"
try:
	clf = joblib.load(model_filename)
except FileNotFoundError:
	print("'model' object-file does not exist.\nRun staticAnalysis_train.py")
	sys.exit(0)


################################# make predictions####################################33
def pred(x):
	if x:
		return 'M'
	else:
		return 'B'

y_pred = clf.predict(x)

rs = []
rs.append(('Name','PredictedLabel'))
for e in range(len(y_pred)):
	name = nm[e].split("/")[-2]
	rs.append((name,pred(y_pred[e])))
df_rs = pd.DataFrame(rs)
df_rs.to_csv(r'static.csv',index=False)