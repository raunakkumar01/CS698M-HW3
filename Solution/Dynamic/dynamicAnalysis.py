import json
import os
# Writing to an excel  
# sheet using Python 
import xlwt 
from xlwt import Workbook


sig_unq = ['creates_largekey', 'recon_fingerprint', 'credential_dumping_lsass_access', 'dropper', 'networkdyndns_checkip', 'nitol', 'creates_shortcut', 'moves_self', 'antivm_generic_services', 'dead_host', 'rat_sdbot', 'memdump_urls', 'overwites_files', 'browser_startpage', 'generates_crypto_key', 'persistence_ads', 'win32_process_create', 'disables_proxy', 'trojan_bublik', 'has_wmi', 'creates_hidden_file', 'infostealer_bitcoin', 'stealth_hidden_extension', 'antidbg_devices', 'suspicious_command_tools', 'modifies_certificates', 'allocates_rwx', 'antivm_network_adapters', 'persistence_registry_javascript', 'installs_bho', 'disables_security', 'dumped_buffer2', 'dyreza', 'antivm_generic_ide', 'infostealer_ftp', 'network_http_post', 'rat_teamviewer', 'injection_write_memory_exe', 'uses_windows_utilities', 'antivm_vbox_files', 'antisandbox_idletime', 'stealth_system_procname', 'antiav_servicestop', 'antivm_vbox_keys', 'network_http', 'sniffer_winpcap', 'infostealer_keylogger', 'removes_zoneid_ads', 'antivirus_virustotal', 'bypass_firewall', 'cloud_rapidshare', 'banker_zeus_p2p', 'shutdown_system', 'spreading_autoruninf', 'antivm_generic_cpu', 'deepfreeze_mutex', 'cloud_mega', 'creates_service', 'antivm_memory_available', 'antivm_vbox_devices', 'self_delete_bat', 'antidbg_windows', 'stops_service', 'locates_sniffer', 'privilege_luid_check', 'suspicious_tld', 'disables_system_restore', 'antivm_disk_size', 'network_cnc_http', 'detect_putty', 'recon_programs', 'suspicious_write_exe', 'antiav_detectreg', 'antiav_detectfile', 'process_interest', 'network_bind', 'protection_rx', 'infostealer_mail', 'modifies_desktop_wallpaper', 'p2p_cnc', 'rat_bifrose', 'recon_systeminfo', 'antisandbox_restart', 'ransomware_extensions', 'stealth_window', 'antivm_firmware', 'upatre', 'installs_appinit', 'credential_dumping_lsass', 'stealth_hiddenfile', 'antivm_vmware_in_instruction', 'bagle', 'antivm_generic_bios', 'console_output', 'locates_browser', 'ransomware_file_moves', 'creates_doc', 'antisandbox_sleep', 'nolookup_communication', 'banker_bancos', 'ransomware_dropped_files', 'injection_runpe', 'dumped_buffer', 'terminates_remote_process', 'process_martian', 'disables_app_launch', 'deletes_self', 'modifies_security_center_warnings', 'deletes_executed_files', 'process_needed', 'ransomware_message', 'raises_exception', 'worm_kolabc', 'rat_pcclient', 'checks_debugger', 'rat_xtreme', 'injection_thread', 'injection_write_memory', 'av_detect_china_key', 'persistance_registry_javascript', 'persistence_autorun', 'modifies_firefox_configuration', 'wmi_antivm', 'network_icmp', 'exec_crash', 'antiemu_wine', 'ransomware_appends_extensions', 'antivm_vmware_keys', 'antisandbox_cuckoo_files', 'browser_security', 'infostealer_browser', 'multiple_useragents', 'antisandbox_mouse_hook', 'antisandbox_foregroundwindows', 'antivm_generic_disk', 'injection_modifies_memory', 'antivm_generic_scsi', 'antivm_queries_computername', 'reads_user_agent', 'suspicious_process']
ntw_unq = ['udp','http']#['udp','irc','http','smtp','tcp','hosts','dns','domains','icmp']
catg = ['process','system','file','misc']
wb = Workbook()

beh_sm_f = 9 + len(catg)
sheet1 = wb.add_sheet('Sheet 1') 
sheet1.write(0, 2, 'File Created') 
sheet1.write(0, 3, 'File Deleted') 
sheet1.write(0, 4, 'Directory Created') 
sheet1.write(0, 5, 'Regkey Opened') 
sheet1.write(0, 6, 'File Written')
sheet1.write(0, 7, 'DLL Loaded') 
sheet1.write(0, 8, 'API Stats')
# sheet1.write(0, 9, 'Unique DLL')
sheet1.write(0, 9, 'Unique API')
sheet1.write(0, 1, 'Predicted Label')
for e in range(len(catg)):
	val = catg[e]
	sheet1.write(0, beh_sm_f-len(catg)+e+1, val)
for e in range(len(ntw_unq)):
	sheet1.write(0, beh_sm_f+e+1, ntw_unq[e])
for e in range(len(sig_unq)):
	val = sig_unq[e]
	sheet1.write(0, beh_sm_f+len(ntw_unq)+e+1, val)


##################################################Malware#######################################

file_list = []
def get_files(path):
	dir_entries = os.listdir(path)
	for entry in dir_entries:
		sub_dir = os.listdir(path+entry+'/')
		if(len(sub_dir)>0):
			for file in sub_dir:
				file_list.append(path+entry+'/'+file)


get_files('Malware/')

for file in range(len(file_list)):#
	with open(file_list[file]) as f:
		print('M'+str(file))
		data = json.load(f)
		sheet1.write((file+1), 0, f.name)
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
		dic = {}
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
		sheet1.write((file+1),2, file_created)
		sheet1.write((file+1),3, file_deleted)
		sheet1.write((file+1),4, directory_created)
		sheet1.write((file+1),5, regkey_opened)
		sheet1.write((file+1),6, file_written)
		sheet1.write((file+1),7, len(dll))
		sheet1.write((file+1),8, api)
		# sheet1.write((file+1),9, len(list(dll_unq)))
		sheet1.write((file+1),9, len(list(api_unq)))
		sheet1.write((file+1),1, 'M')
		for e in range(len(catg)):
			sheet1.write((file+1),beh_sm_f-len(catg)+e+1, dic[catg[e]])



		if data['network']:#for each of the network utilities count the number times packet were sent and recieved
			for e in range(len(ntw_unq)):
				if ntw_unq[e] in data['network']:
					val =0
					val += len(data['network'][ntw_unq[e]])
					sheet1.write((file+1), beh_sm_f+e+1, val)

		if data['signatures']:#for each of th eunique signatures check if it is present or not
			for e in range(len(data['signatures'])):
				sig_l.append(list(data['signatures'])[e]['name'])
			for e in range(len(sig_unq)):
				val = sig_unq[e]
				if val in sig_l:
					sheet1.write((file+1), beh_sm_f+len(ntw_unq)+e+1, 1)
				else :
					sheet1.write((file+1), beh_sm_f+len(ntw_unq)+e+1, 0)
len_m = len(file_list)
####################################################BENIGN########################################3
def get_files_B(path):
	dir_entries = os.listdir(path)
	for file in dir_entries:
		file_list.append(path+file)

file_list = []
get_files_B('Benign/')
for file in range(len(file_list)):#
	with open(file_list[file]) as f:
		print(file)
		data = json.load(f)
		sheet1.write((file+len_m+1), 0, f.name)
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
		dic = {}
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
		sheet1.write((file+len_m+1),2, file_created)
		sheet1.write((file+len_m+1),3, file_deleted)
		sheet1.write((file+len_m+1),4, directory_created)
		sheet1.write((file+len_m+1),5, regkey_opened)
		sheet1.write((file+len_m+1),6, file_written)
		sheet1.write((file+len_m+1),7, len(dll))
		sheet1.write((file+len_m+1),8, api)
		# sheet1.write((file+len_m+1),9, len(list(dll_unq)))
		sheet1.write((file+len_m+1),9, len(list(api_unq)))
		sheet1.write((file+len_m+1),1, 'B')
		for e in range(len(catg)):
			sheet1.write((file+len_m+1),beh_sm_f-len(catg)+e+1, dic[catg[e]])

		if data['network']:#for each of the network utilities count the number times packet were sent and recieved
			for e in range(len(ntw_unq)):
				if ntw_unq[e] in data['network']:
					val =0
					val += len(data['network'][ntw_unq[e]])
					sheet1.write((file+len_m+1), beh_sm_f+e+1, val)
		if data['signatures']:#for each of the unique signatures check if it is present or not
			for e in range(len(data['signatures'])):
				sig_l.append(list(data['signatures'])[e]['name'])
			for e in range(len(sig_unq)):
				val = sig_unq[e]
				if val in sig_l:
					sheet1.write((file+len_m+1), beh_sm_f+len(ntw_unq)+e+1, 1)
				else :
					sheet1.write((file+len_m+1), beh_sm_f+len(ntw_unq)+e+1, 0)

wb.save('DynamicAnalysis.xlt')