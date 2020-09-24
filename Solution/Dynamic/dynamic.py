# -*- coding: utf-8 -*-
import numpy as np
import pandas as pd
import joblib
import sys
from sklearn.metrics import confusion_matrix, accuracy_score, f1_score
import pathlib
import re
import json
import os
# Extract data
sig_unq = ['creates_largekey', 'recon_fingerprint', 'credential_dumping_lsass_access', 'dropper', 'networkdyndns_checkip', 'nitol', 'creates_shortcut', 'moves_self', 'antivm_generic_services', 'dead_host', 'rat_sdbot', 'memdump_urls', 'overwites_files', 'browser_startpage', 'generates_crypto_key', 'persistence_ads', 'win32_process_create', 'disables_proxy', 'trojan_bublik', 'has_wmi', 'creates_hidden_file', 'infostealer_bitcoin', 'stealth_hidden_extension', 'antidbg_devices', 'suspicious_command_tools', 'modifies_certificates', 'allocates_rwx', 'antivm_network_adapters', 'persistence_registry_javascript', 'installs_bho', 'disables_security', 'dumped_buffer2', 'dyreza', 'antivm_generic_ide', 'infostealer_ftp', 'network_http_post', 'rat_teamviewer', 'injection_write_memory_exe', 'uses_windows_utilities', 'antivm_vbox_files', 'antisandbox_idletime', 'stealth_system_procname', 'antiav_servicestop', 'antivm_vbox_keys', 'network_http', 'sniffer_winpcap', 'infostealer_keylogger', 'removes_zoneid_ads', 'antivirus_virustotal', 'bypass_firewall', 'cloud_rapidshare', 'banker_zeus_p2p', 'shutdown_system', 'spreading_autoruninf', 'antivm_generic_cpu', 'deepfreeze_mutex', 'cloud_mega', 'creates_service', 'antivm_memory_available', 'antivm_vbox_devices', 'self_delete_bat', 'antidbg_windows', 'stops_service', 'locates_sniffer', 'privilege_luid_check', 'suspicious_tld', 'disables_system_restore', 'antivm_disk_size', 'network_cnc_http', 'detect_putty', 'recon_programs', 'suspicious_write_exe', 'antiav_detectreg', 'antiav_detectfile', 'process_interest', 'network_bind', 'protection_rx', 'infostealer_mail', 'modifies_desktop_wallpaper', 'p2p_cnc', 'rat_bifrose', 'recon_systeminfo', 'antisandbox_restart', 'ransomware_extensions', 'stealth_window', 'antivm_firmware', 'upatre', 'installs_appinit', 'credential_dumping_lsass', 'stealth_hiddenfile', 'antivm_vmware_in_instruction', 'bagle', 'antivm_generic_bios', 'console_output', 'locates_browser', 'ransomware_file_moves', 'creates_doc', 'antisandbox_sleep', 'nolookup_communication', 'banker_bancos', 'ransomware_dropped_files', 'injection_runpe', 'dumped_buffer', 'terminates_remote_process', 'process_martian', 'disables_app_launch', 'deletes_self', 'modifies_security_center_warnings', 'deletes_executed_files', 'process_needed', 'ransomware_message', 'raises_exception', 'worm_kolabc', 'rat_pcclient', 'checks_debugger', 'rat_xtreme', 'injection_thread', 'injection_write_memory', 'av_detect_china_key', 'persistance_registry_javascript', 'persistence_autorun', 'modifies_firefox_configuration', 'wmi_antivm', 'network_icmp', 'exec_crash', 'antiemu_wine', 'ransomware_appends_extensions', 'antivm_vmware_keys', 'antisandbox_cuckoo_files', 'browser_security', 'infostealer_browser', 'multiple_useragents', 'antisandbox_mouse_hook', 'antisandbox_foregroundwindows', 'antivm_generic_disk', 'injection_modifies_memory', 'antivm_generic_scsi', 'antivm_queries_computername', 'reads_user_agent', 'suspicious_process']
ntw_unq = ['udp','http']#['udp','irc','http','smtp','tcp','hosts','dns','domains','icmp']
catg = ['process','system','file','misc']
path = pathlib.Path('/home/raunak/COursework/2SEM/CS698m/HW3/Dynamic')

def extract():
	##############################Find all the path names#########################3
	# path = pathlib.Path('/home/raunak/Downloads/Static_Analysis_RAWDATA')
	file_list = [ f for f in path.glob('**/*.json')]

	fet = []
	zero =0
	###################################Extract the features#############################
	for file in range(len(file_list)):#2):#
		with open(file_list[file]) as f:
			data = json.load(f)
			# sheet1.write((file+1), 0, f.name)
			dic ={}
			dic['Nmae'] = f.name
			file_created = 0
			file_deleted = 0
			file_written = 0
			directory_created = 0
			regkey_opened = 0
			dll = []
			dll_unq = set()
			api = 0
			api_unq = set()
			ntw = 0
			sig_l = []
			dic['FileCreated'] = file_created
			dic['FileDeleted'] = file_deleted
			dic['DirectoryCreated'] = directory_created
			dic['RegKeyOpened'] = regkey_opened
			dic['FileWritten'] = file_written
			dic['DLLloaded'] = len(dll)
			dic['ApiStats'] = api
			dic['UniqueAPI'] = len(api_unq)
			for v in catg:
				dic[v] = 0
			if data['behavior'] and 'summary' in data['behavior']:			
				if 'file_created' in data['behavior']['summary']:
					file_created+=len(data['behavior']['summary']['file_created'])
				if 'file_deleted' in data['behavior']['summary']:
					file_deleted+=len(data['behavior']['summary']['file_deleted'])
				if 'directory_created' in data['behavior']['summary']:
					directory_created+=len(data['behavior']['summary']['directory_created'])
				if 'regkey_opened' in data['behavior']['summary']:
					regkey_opened+=len(data['behavior']['summary']['regkey_opened'])
				if 'file_written' in data['behavior']['summary']:
					file_written+=len(data['behavior']['summary']['file_written'])
				if 'dll_loaded' in data['behavior']['summary']:
					dll +=data['behavior']['summary']['dll_loaded']
					for e in data['behavior']['summary']['dll_loaded'] :
						dll_unq.add(e.split("\\")[-1])
				if 'apistats' in data['behavior']:
					keys = data['behavior']['apistats']
					for key in keys:
						api += sum(data['behavior']['apistats'][key].values())
						elm = data['behavior']['apistats'][key].keys()
						for e in elm:
							api_unq.add(e)
				if 'processes' in data['behavior']:
					keys = data['behavior']['processes']
					for e in  keys:
						if e['calls']:
							calls_all = e['calls']
							for i in range(len(calls_all)):
								value =e['calls'][i]['category']
								if value in catg:
									dic[value] +=  1
			dic['FileCreated'] = file_created
			dic['FileDeleted'] = file_deleted
			dic['DirectoryCreated'] = directory_created
			dic['RegKeyOpened'] = regkey_opened
			dic['FileWritten'] = file_written
			dic['DLLloaded'] = len(dll)
			dic['ApiStats'] = api
			dic['UniqueAPI'] = len(api_unq)
			if data['network']:#for each of the network utilities count the number times packet were sent and recieved
				for e in range(len(ntw_unq)):
					if ntw_unq[e] in data['network']:
						val =0
						val += len(data['network'][ntw_unq[e]])
						dic[ntw_unq[e]] = val
			for e in ntw_unq:
				if e not in dic:
					dic[e] = 0
			if data['signatures']:#for each of th eunique signatures check if it is present or not
				for e in range(len(data['signatures'])):
					sig_l.append(list(data['signatures'])[e]['name'])
				for e in range(len(sig_unq)):
					val = sig_unq[e]
					if val in sig_l:
						dic[sig_unq[e]] = zero + 1
					else :
						dic[sig_unq[e]] = zero
			for e in sig_unq:
				if e not in dic:
					dic[e] = 0
			fet.append(dic)	
	df_fet = pd.DataFrame(fet)
	# df_fet.to_csv(r'file_test_fet_1.csv',index=False)
	return df_fet 

# extract()
################################### Load the data #################################
path = pathlib.Path(input("Enter path :"))
df_fet = extract()#pd.read_csv('file_test_fet_1.csv')
x = np.array(df_fet.iloc[:, 1:15])
x=np.delete(x,12,1)
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
	name = nm[e].split("/")[-1]
	rs.append((name,pred(y_pred[e])))
df_rs = pd.DataFrame(rs)
df_rs.to_csv(r'dynamic.csv',index=False)