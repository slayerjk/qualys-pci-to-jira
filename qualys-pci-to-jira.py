#!/usr/bin/env python3

'''
This script is automatization of creating Jira tickets,
based on Qualys PCI scan report.
'''

import logging
from datetime import datetime, date, timedelta
from time import sleep
from os import mkdir, path, remove
from sys import exit
from pathlib import Path
import requests
import json
import re
from tempfile import TemporaryFile
from smtplib import SMTP
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

### DEFINING WORK DIR(SCRIPT'S LOCATION) ###
work_dir = '<YOUR ABSOLUTE PATH>'

### SCRIPT APPNAME(FOR SEND MAIL FUNCTION & ETC)
appname = 'qualys-pci-to-jira'

###########################
##### LOGGING SECTION #####
today = datetime.now()
jira_date_format = date.today()
logs_dir = work_dir+'/logs'

if not path.isdir(logs_dir):
    mkdir(logs_dir)

app_log_name = logs_dir+'/qualys-pci-to-jira_log_' + \
    str(today.strftime('%d-%m-%Y'))+'.log'

logging.basicConfig(filename=app_log_name, filemode='w', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%d-%b-%Y %H:%M:%S')

logging.info('SCRIPT WORK STARTED: QUALYS PCI REPORT TO JIRA TICKET')
logging.info('Script Starting Date&Time is: ' +
             str(today.strftime('%d/%m/%Y %H:%M:%S')) + '\n')

### EMAIL REPORT FUNCTION ###
'''
To send email report.
By default, at the end of the script only.
'''
### SMTP DATA(WITHOUT AUTH) ###
'''
Email report
'''
send_mail_option = 'yes'
smtp_server = '<YOUR SMTP SERVER>'
from_addr = f'{appname}@EXAMPLE.COM'
to_addr_list_users = ['USER1@EXAMPLE.COM', 'USER2@EXAMPLE.COM']
to_addr_list_admins = ['ADMIN1@EXAMPLE.COM']
smtp_port = 25

def send_mail_report(type):
    message = MIMEMultipart()
    message["From"] = from_addr

    if send_mail_option == 'yes':
        
        if type == 'error':
            logging.info('START: sending email error report')
            message["Subject"] = f'{appname} - Script Error({today})'
            message["To"] = ', '.join(to_addr_list_admins)
            rcpt_to = to_addr_list_admins
        elif type == 'report':
            logging.info('START: sending jira tasks final report')
            message["Subject"] = f'{appname} - Результат({today})'
            message["To"] = ', '.join(to_addr_list_users)
            rcpt_to = to_addr_list_users
            user_report_temp.seek(0)
        elif type == 'log':
            logging.info('START: sending email final report')
            message["Subject"] = f'{appname} - Script Report({today})'
            message["To"] = ', '.join(to_addr_list_admins)
            rcpt_to = to_addr_list_admins
        
        if type == 'error' or type == 'log':
            with open(app_log_name, 'r') as log:
                input_file = log.read()
        elif type == 'report':
            input_file = user_report_temp.read()

        message.attach(MIMEText(input_file, "plain"))
        body = message.as_string()
        
        try:
            with SMTP(smtp_server, smtp_port) as send_mail:
                send_mail.ehlo()
                send_mail.sendmail(from_addr, rcpt_to, body)
                send_mail.quit()
                if type == 'error' or type == 'log':
                    logging.info('DONE: sending email error report\n')
                elif type == 'report':
                    logging.info('DONE: user final report\n')
        except Exception as e:
            if type == 'error':
                logging.exception('FAILED: sending email error report, moving on...\n')
            else:
                logging.exception('FAILED: sending email final report, moving on...\n')

######################################################################
##### DEFINING ALL NECESSARRY FOLDERS/FILES & API URLS VARIABLES #####

### LIST OF FOLDERS TO CREATE DIRS ###
list_of_folders = []

### DEFINING ALL NECESSARRY FOLDERS ###
jira_files_dir = work_dir+'/jira_files'
list_of_folders.append((jira_files_dir))

### DEFINING FILES VARIABLES ###
script_data = work_dir+'/script-data'
jira_query_task_template = jira_files_dir+'/jira-query-task-template.json'
jira_query_subtask_template = jira_files_dir+'/jira-query-subtask-template.json'
jira_temp_query_file = jira_files_dir+'/jira-temp-query.json'

### PROXY ###
proxies = {
    'http': 'http://proxy-ws.cbank.kz:8080',
    'https': 'http://proxy-ws.cbank.kz:8080',
}

### VALIDATING CREDS ###
'''
Script-data file contains following:
# qualys api base64 creds(user:pass)
<qualys_base64creds(user:pass)>
# jira api base64 creds(user:pass)
<jira_base64creds(user:pass)>
'''
if not path.isfile(script_data):
    logging.error('FAILURE: script-data file NOT FOUND, exiting...')
    send_mail_report('error')
    exit()
with open(script_data, 'r', encoding='utf-8') as file:
    data = [i.strip() for i in file.readlines()]
    qualys_pci_api_root_url = data[1]
    qualys_api_coded_creds = data[3]
    jira_base_url = data[5]
    jira_api_coded_creds = data[7]

### QUALYS PCI API VARS ###
qualys_pci_api_vuln_url = qualys_pci_api_root_url+'/pci/vuln'
qualys_pci_api_vuln_list_url = qualys_pci_api_vuln_url+'/list'
qualys_query_headers = {
    'Authorization': 'Basic '+qualys_api_coded_creds,
    'X-Requested-With': 'qualys-pci-to-jira-script',
}

### JIRA API VARS ###
jira_api_url = f'{jira_base_url}/rest/api/2/issue/'
jira_query_headers = {
    'Authorization': 'Basic '+jira_api_coded_creds,
    'X-Requested-With': 'qualys-to-jira-script',
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

jira_tasks_count = 0
jira_subtasks_count = 0

### JIRA TASK-PROCESSED VULN IPs ###
processed_vuln_ips = {}

### REGEXP PATTERN TO SEARCH QUALYS CVSS BASE VALUE ###
cvss_base_pattern = '^(\d+)\.?'

### JIRA TASK KEYS LIST AND SEARCH KEY REGEXP PATTERN ###
jira_task_keys = []
jira_task_parent_key = ''
jira_task_key_pattern = '^.*"key":"(.*)",.*$'

#####################
##### FUNCTIONS #####

### ENCAPSULATING VULN DETAILS VALUES TO JIRA TASK QUERY AND MAKE QUERY ###
def make_jira_task():
    logging.info(
        'Starting to encapsulate Qualys vuln details data to JIRA TASK query...')
    global jira_task_parent_key
    global jira_task_keys
    global jira_tasks_count
    try:
        with open(jira_query_task_template, 'r', encoding='utf_8_sig') as reader, open(jira_temp_query_file, 'w', encoding='utf_8_sig') as writer:
            temp_data = json.loads(reader.read())
            temp_data['fields']['summary'] = vuln_ip + ' - ' + vuln_dns
            temp_data['fields']['priority']['name'] = 'Highest'
            temp_data['fields']['description'] = 'Внешние информационные активы'
            temp_data['fields']['duedate'] = str(
                jira_date_format + timedelta(days=+90))
            ### 'CUSTOMFIELD_10200' STANDS FOR START DATE ###
            temp_data['fields']['customfield_10200'] = str(
                jira_date_format)
            insert_data = json.dumps(temp_data, indent=4)
            writer.write(insert_data)
            writer.close()
            
            ### MAKE JSON QUERY(TASK) TO JIRA API ###
            logging.info('Sending JSON data(TASK) to Jira API...')
            try:
                jira_api_request = requests.post(jira_api_url, data=open(
                    jira_temp_query_file, 'rb'), headers=jira_query_headers)
            except Exception as error:
                logging.exception(
                    'FAILURE: failed to send JSON data(TASK) to Jira API, exiting...')
                send_mail_report('error')
                exit()
            if jira_api_request.status_code == 201:
                jira_tasks_count += 1
                logging.info(jira_api_request.text)
                logging.info(
                    'Sending JSON data(TASK) to Jira API - DONE!')
                
                user_report_temp.write(f'\nJIRA TASK(ID is: {id}; IP is: {vuln_ip}):\n{str(jira_api_request.text)}\n')
                
                jira_task_parent_key = re.findall(jira_task_key_pattern, jira_api_request.text)[0]
                jira_task_keys.append(f'TASK: {re.findall(jira_task_key_pattern, jira_api_request.text)[0]}')
            else:
                logging.warning(
                    'Something wrong, check this status code: ' + str(jira_api_request.status_code))
                logging.warning(jira_api_request.text)
                send_mail_report('error')
                exit()
    except Exception as error:
        logging.exception(
            'FAILURE: Failed to encapsulate Qualys vuln details data to JIRA query, exiting...')
        send_mail_report('error')
        exit()

### ENCAPSULATING VULN DETAILS VALUES TO JIRA SUB-TASK QUERY ###
def make_jira_subtask():
    logging.info(
        'Starting to encapsulate Qualys vuln details data to JIRA SUB-TASK query...')
    global jira_task_parent_key
    global jira_task_keys
    global jira_subtasks_count
    try:
        with open(jira_query_subtask_template, 'r', encoding='utf_8_sig') as reader, open(jira_temp_query_file, 'w', encoding='utf_8_sig') as writer:
            temp_data = json.loads(reader.read())
            temp_data['fields']['parent']['key'] = jira_task_parent_key
            temp_data['fields']['summary'] = vuln_title
            temp_data['fields']['description'] = vuln_threat
            #temp_data['fields']['customfield_11616'] = OS
            temp_data['fields']['customfield_11612'] = vuln_qid
            #temp_data['fields']['customfield_11617'] = Vuln_Status
            #temp_data['fields']['customfield_11615'] = Severity
            temp_data['fields']['customfield_11618'] = vuln_port
            #temp_data['fields']['customfield_11619'] = First_Detected
            #temp_data['fields']['customfield_11620'] = Last_Detected
            temp_data['fields']['customfield_11621'] = str(','.join(vuln_cveId))
            temp_data['fields']['customfield_11622'] = vuln_cvssBase
            temp_data['fields']['customfield_11624'] = vuln_impact
            temp_data['fields']['customfield_11625'] = vuln_solution + '\n\n' + vuln_patch
            temp_data['fields']['customfield_11626'] = vuln_result
            temp_data['fields']['customfield_11627'] = 'YES'
            ### 'CUSTOMFIELD_10200' STANDS FOR START DATE ###
            temp_data['fields']['customfield_10200'] = str(
                jira_date_format)
            ### CALCULATING PRIORITY AND DUEDATE ###
            try:
                if int(re.findall(cvss_base_pattern, vuln_cvssBase)[0]) >= 8:
                    temp_data['fields']['priority']['name'] = 'Highest'
                    temp_data['fields']['duedate'] = str(
                        jira_date_format + timedelta(days=+15))
                elif int(re.findall(cvss_base_pattern, vuln_cvssBase)[0]) >= 6:
                    temp_data['fields']['priority']['name'] = 'High'
                    temp_data['fields']['duedate'] = str(
                        jira_date_format + timedelta(days=+30))
                elif int(re.findall(cvss_base_pattern, vuln_cvssBase)[0]) >= 4:
                    temp_data['fields']['priority']['name'] = 'Medium'
                    temp_data['fields']['duedate'] = str(
                        jira_date_format + timedelta(days=+45))
                elif int(re.findall(cvss_base_pattern, vuln_cvssBase)[0]) >= 2:
                    temp_data['fields']['priority']['name'] = 'Low'
                    temp_data['fields']['duedate'] = str(
                        jira_date_format + timedelta(days=+60))
                elif int(re.findall(cvss_base_pattern, vuln_cvssBase)[0]) >= 1:
                    temp_data['fields']['priority']['name'] = 'Lowest'
                    temp_data['fields']['duedate'] = str(
                        jira_date_format + timedelta(days=+90))
            except IndexError:
                logging.exception(f'FAILURE: check vuln_cvssBase{vuln_cvssBase}({id},{vuln_qid}), exiting')
                send_mail_report('error')
                exit()
            insert_data = json.dumps(temp_data, indent=4)
            writer.write(insert_data)
            writer.close()
            
            ### SEND JSON QUERY(SUB-TASK) TO JIRA API ###
            logging.info('Sending JSON data(SUB-TASK) to Jira API...')
            try:
                jira_api_request = requests.post(jira_api_url, data=open(jira_temp_query_file, 'rb'), headers=jira_query_headers)
            except Exception as error:
                logging.exception(
                    'FAILURE: failed to send JSON data(SUB-TASK) to Jira API, exiting...')
                send_mail_report('error')
                exit()
            if jira_api_request.status_code == 201:
                logging.info(
                    'Sending JSON data(SUB-TASK) to Jira API - DONE!')
                jira_subtasks_count += 1
                logging.info(str(jira_api_request.text))
                
                user_report_temp.write(f'JIRA SUB-TASK(ID is: {id}; IP is {vuln_ip}; QID is {vuln_qid}):\n{str(jira_api_request.text)}\n')
                
                jira_task_keys.append(f'SUB-TASK: {re.findall(jira_task_key_pattern, jira_api_request.text)[0]}')
                logging.info(
                    'Sleeping for 1 seconds before next request...\n')
                sleep(1)
            else:
                logging.warning(
                    'Something wrong, check this status code: ' + str(jira_api_request.status_code))
                logging.warning(jira_api_request.text)
                send_mail_report('error')
                exit()
    except Exception as error:
        logging.exception(
            'FAILURE: Failed to encapsulate Qualys vuln details data to JIRA query, exiting...')
        send_mail_report('error')
        exit()

### FILES ROTATION ###
### DEFINE HOW MANY FILES TO KEEP(MOST RECENT) ###
logs_to_keep = 30
reports_to_keep = 30

def files_rotate(path_to_rotate, num_of_files_to_keep):
    count_files_to_keep = 1
    basepath = sorted(Path(path_to_rotate).iterdir(),
                      key=path.getctime, reverse=True)
    for entry in basepath:
        if count_files_to_keep > num_of_files_to_keep:
            remove(entry)
            logging.info('removed file is: '+str(entry))
        count_files_to_keep += 1

### ESTIMATED TIME ###
def count_script_job_time():
    end_date = datetime.now()
    return f'\nEstimated time is: {str(end_date - today)}\n##########\n'

#############################
##### PRE-START ACTIONS #####
logging.info('STARTED: PRE-START ACTIONS')

### CHECKING JIRA TEMPLATES EXISTS ###
if not path.isfile(jira_query_task_template):
    logging.exception(
        'FAILURE: Jira query Task template NOT FOUND, exiting...')
    send_mail_report('error')
    exit()

if not path.isfile(jira_query_subtask_template):
    logging.exception(
        'FAILURE: Jira query Sub-Task template NOT FOUND, exiting...')
    send_mail_report('error')
    exit()

### CREATING ALL NECESSARRY FOLDERS ###
logging.info('Starting to create all necessarry folders...')
for folder in list_of_folders:
    try:
        if mkdir(folder):
            logging.info(folder+': created')
    except FileExistsError as error:
        logging.info(folder+': exists, skipping')

if not path.isfile(jira_query_task_template):
    logging.exception(
        'FAILURE: Jira query Task template NOT FOUND, exiting...')
    send_mail_report('error')
    exit()

if not path.isfile(jira_query_subtask_template):
    logging.exception(
        'FAILURE: Jira query Sub-Task template NOT FOUND, exiting...')
    send_mail_report('error')
    exit()

logging.info('DONE: PRE-START ACTIONS\n')

### CREATING USER REPORT FILE ###
user_report_temp = TemporaryFile('w+t')
user_report_temp.write(f'SCRIPT WORK STARTED QUALYS - {today}\n\n')

### QUALYS GET VULN LIST ###
logging.info('STARTED: to get Qualys Vulns list')
try:
    qualys_get_vulns_list = requests.get(
        qualys_pci_api_vuln_list_url, headers=qualys_query_headers)
    # print(qualys_get_vuln_list.json)
except Exception as error:
    logging.exception('FAILURE: to get Qualys Vulns list, exiting...')
    send_mail_report('error')
    exit()
logging.info('DONE: to get Qualys Vulns list\n')

### MAKE LIST OF QUALYS VULNS ID's ###
logging.info('STARTED: getting vulns list')
vulns_data = json.loads(qualys_get_vulns_list.text)
logging.info(f'Current qaulys vuln data:\n{qualys_get_vulns_list.text}')
try:
    qualys_vuln_data = vulns_data['data']['merchantVulnList']
    qualys_vuln_ids_list = [qualys_vuln_data[data]['id'] for data in range(len(qualys_vuln_data)) if qualys_vuln_data[data]['pciCompliant'] != 'Pass']
except KeyError as e:
    logging.exception('FAILURE: getting vulns list, no VULNS found, exiting')
    send_mail_report('error')
    exit()
logging.info('DONE: getting vulns list\n')
user_report_temp.write(f'Qualys vulnd IDs list to process:\n{qualys_vuln_ids_list}\n')

### GET QUALYS VULN DETAILS ###
for id in qualys_vuln_ids_list:
    qualys_pci_api_vuln_detail_url = qualys_pci_api_vuln_url + \
        '/'+str(id)+'/details'
    try:
        qualys_get_vuln_detail = requests.get(
            qualys_pci_api_vuln_detail_url, headers=qualys_query_headers, proxies=proxies)
        # print(qualys_get_vuln_list.json)
    except Exception as error:
        logging.exception('FAILURE: to get Qualys Vuln details, exiting...')
        send_mail_report('error')
        exit()
    
    ### PARSING VULN DETAILS VALUES ###
    vuln_details = json.loads(qualys_get_vuln_detail.text)
    # print(vuln_details)
    # break
    vuln_details_data = vuln_details['data']
    ### PARSING VULN DETAILS VALUES ###
    vuln_title = str(vuln_details_data['title'])
    vuln_ip = str(vuln_details_data['ip'])
    vuln_dns = str(vuln_details_data['dns'])
    vuln_qid = str(vuln_details_data['qid'])
    vuln_cvssBase = str(vuln_details_data['cvssBase'])
    vuln_port = str(vuln_details_data['port'])
    try:
        if len(vuln_details_data['cveList']) == 0:
            logging.warning(f'WARNING: no CVE found for {id}-{vuln_qid}, leaving blank')
            vuln_cveId = ['NA']
        else:
            vuln_cveId = [vuln_details_data['cveList'][ind]['urlText'] for ind in range(len(vuln_details_data['cveList']))]
    except IndexError:
        logging.exception(f'FAILURE: check "cveList/urlText"({vuln_cveId}) for {id}-{vuln_qid}, exiting')
        send_mail_report('error')
        exit()
    vuln_threat = str(vuln_details_data['threat'])
    vuln_impact = str(vuln_details_data['impact'])
    vuln_solution = str(vuln_details_data['solution'])
    vuln_patch = str(vuln_details_data['patch'])
    vuln_result = str(vuln_details_data['result'])
    #vuln_severity = str(vuln_details_data['severity'])
    #vuln_cvssTemporal = str(vuln_details_data['cvssTemporal'])
    #vuln_pciCompliant = str(vuln_details_data['pciCompliant'])
    #vuln_category = str(vuln_details_data['category'])
    #vuln_service = str(vuln_details_data['service'])
    #vuln_protocol = str(vuln_details_data['protocol'])
    #vuln_fpStatus = str(vuln_details_data['fpStatus'])
    #vuln_bugTraqList = str(vuln_details_data['bugTraqList'])
    #vuln_vendorReferenceList = str(vuln_details_data['vendorReferenceList'])
    #vuln_dateLastUpdate = str(vuln_details_data['dateLastUpdate'])

### DEBUG ###
#exit()

    ### CREATE TASK OR SUB-TASK OR TASK AND SUB-TASK ###
    if vuln_ip not in processed_vuln_ips.values():
        logging.info(f'{vuln_ip} is not processed, starting jira TASK creating job')
        make_jira_task()
        processed_vuln_ips[jira_task_parent_key] = vuln_ip
        
        # DEBUG
        #for key, item in processed_vuln_ips.items():
        #   print(f'{key}:{item}')
        logging.info(f'DEBUG: LAST PROCESSED ID: {id}')
        logging.info(f'DEBUG: LAST PROCESSED IP: {vuln_ip}')
        logging.info(f'DEBUG: LAST PROCESSED CVSS_BASE: {vuln_cvssBase}')
        
        logging.info(f'{vuln_ip} is not processed, starting jira SUB-TASK creating job after TASK created')
        make_jira_subtask()
    else:
        '''
        for key in processed_vuln_ips.keys():
            if vuln_ip in processed_vuln_ips.values():
                jira_task_parent_key = key
                break
        '''

        logging.info(f'{vuln_ip} is processed already, starting jira SUB-TASK creating job')
        logging.info(f'Current parent iP is {jira_task_parent_key}')
        make_jira_subtask()

logging.info(
    'DONE: PARSE QUALYS VULN DETAILS & ADD VALUES TO JIRA JSON TEMPLATE AND SEND IT TO JIRA\n')

#####################
##### POST JOBS #####
logging.info('STARTED: POST JOBS')

logging.info('Removing all temporary files:')
try:
    if jira_tasks_count != 0:
        logging.info('Removing temporary Jira query...')
        remove(jira_temp_query_file)
except Exception as error:
    logging.exception(
        'Failed Jira query temp file...\n')

logging.info('Starting log rotation...')
try:
    files_rotate(logs_dir, logs_to_keep)
except Exception as error: 
    logging.exception('FAILURE: failed to rotate logs')
logging.info('Finished log rotation\n')    

logging.info('DONE: POST JOBS\n')

### LOG RESULTS ###
logging.info('SCRIPT WORK DONE: QUALYS REPORT TO JIRA TICKET')

logging.info('LIST OF PROCESSED QUALYS VULNS(IDs):')
for id in qualys_vuln_ids_list:
    logging.info(f'QUALYS ID: {id}')

logging.info('\nJIRA TASKS/SUB-TASKS INFO:')
if jira_tasks_count == 0:
    logging.warning('NO JIRA TASKS CREATED: Qualys report might be empty!')
else:
    user_report_temp.write('-----\n')
    logging.info('Jira TASKS created: ' + str(jira_tasks_count))
    user_report_temp.write(f'Jira TASKS created: {jira_tasks_count}\n')

    logging.info('Jira SUB-TASKS created: ' + str(jira_subtasks_count))
    user_report_temp.write(f'Jira SUB-TASKS created: {jira_subtasks_count}\n\n')
    
    logging.info('LIST of Jira task/sub-task keys created:\n-----')
    user_report_temp.write('LIST of Jira task/sub-task keys created:\n-----\n')
    ### PRINT ALL CREATED JIRA TASKS
    for task in jira_task_keys:
        logging.info(task)
        user_report_temp.write(f'{task}\n')

### SEND FINAL REPORT FOR USERS
user_report_temp.write(f'-----\n{count_script_job_time()}')
send_mail_report('report')

logging.info(f'{count_script_job_time()}')
exit()
