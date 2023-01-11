Qualys PCI Scan Results to Jira
Edit
Description&Workflow
The script is automatization of creating Jira tickets(via Jira API) based on Qualys PCI Compliance report(via Qualys api).

Workflow:
* Get and parse Qualys vulnerabilities list(get /pci/vuln/list);
  * exclude vulnerabilities that has field pciCompliant=Pass, take only with Fail;
* get and parse qualys vuln details(get /pci/vuln/<vuln_id>/details);
* create Jira Task, based on IP field
  * create Jira sub-task based on parent IP

Additions Features
* Log rotation
* Send email(smtp without auth)(can be turned off):
  * errors
  * user-report

<h3>Requirements:</h3>

Tested on Python 3.10.

Modules:
```
download
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
```

Folders and Files in the script's folder(by default):
jira_files - jira templates folder
there MUST be jira template files: jira-query-task-template.json & jira-query-subtask-template.json
logs - logs folder
script-data - your Qualys and Jira base64 creds
Jira Templates
Check your Jira corresponding (custom) fields name and change them in script:

jira-query-task-template.json:
```
{
    "fields": {
        "project": {
            "key": "<YOUR JIRA PROJECT KEY>"
        },
        "issuetype": {
            "name": "Task"
        },
        "summary": "",
        "assignee": {
            "name": "<YOUR JIRA ASSIGNEE NAME>"
        },
        "customfield_10200": "",
        "duedate": "",
        "description": "",
        "priority": {
            "name": ""
        },
        "customfield_11024": [
            {
                "key": "<MY CUSTOM DATA>"
            }
        ]
    }
}
```

jira-query-subtask-template.json:
```
{
    "fields": {
        "project": {
            "key": "<YOUR JIRA PROJECT KEY>"
        },
		"parent": {
            "key": ""
        },
        "issuetype": {
            "name": ""
        },
        "summary": "",
        "assignee": {
            "name": "<YOUR JIRA ASSIGNEE NAME>"
        },
		"customfield_11616": "",
		"customfield_11612": "",
		"customfield_11617": "",
		"customfield_11615": "",
		"customfield_11618": "",
		"customfield_11619": "",
		"customfield_11620": "",
		"customfield_11621": "",
		"customfield_11622": "",
		"customfield_11624": "",
		"customfield_11625": "",
		"customfield_11626": "",
		"customfield_11627": "",
        "customfield_10200": "",
        "duedate": "",
        "description": "",
        "priority": {
            "name": ""
        },
        "customfield_11024": [
            {
                "key": "<MY CUSTOM DATA>"
            }
        ]
    }
}
```

Script Data

Lines order of these file are important
```
# qualys api base64 creds(user:pass)
<YOUR QUALYS ACCOUNT:PASSWORD BASE64 STRING>
# jira api base64 creds(user:pass)
<YOUR JIRA ACCOUNT:PASSWORD BASE64 STRING>
```
