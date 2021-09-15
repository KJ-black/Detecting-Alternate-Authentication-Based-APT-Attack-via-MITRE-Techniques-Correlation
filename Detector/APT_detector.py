from APT.APT_C2 import *
from APT.APT_Lateral import *
from Credentials import config


"""
Some basic info of enviroment, need to be modified to fit yours:
- es_host: ELK log server
- config.es.host, config.es.cred: ELK authentication
- es.time: The duration inspected by detector
- hosts: Hosts in your enviroment
- ip2host: The mapping from IPs to your hosts
- router: Router in your enviroment
- C2_whitelist_ip, C2_whitelist_port: Safe IPs/ports
"""
es_host = 'https://140.113.194.82:9200'
es = elk.ElasticSearch(config.es.host, config.es.cred)
es.time('2021-06-15T06:30:00.000Z', '2021-06-15T07:30:00.000Z')

hosts = ["victim2", "ad"]
ip2host = {"192.168.1.112": "victim2", "192.168.1.113": "ad"}
router = "router"
C2_whitelist_ip = ['239.255.255.250', '224.0.0.251', '224.0.0.252']
C2_whitelist_port = [137]


"""
Calculate the time intervals between each of the same connection, and remove the outliers.
"""
patterns = C2_detect(es, router)

"""
Print the suspicious connections which are:
- Not ipv6
- Not in the whitelist
- Not in the same subnet
- Regularly and Frequently enough
"""
C2_patterns = []
for pattern in patterns:
    if ":" in pattern.id_orig_h or ":" in pattern.id_resp_h or pattern.id_resp_h in C2_whitelist_ip or pattern.id_resp_p in C2_whitelist_port \
        or "192.168.1." in pattern.id_resp_h \
        or pattern.log_itvl_var > 1 \
        or pattern.log_count < 3:
        continue

    print('%s had a suspicious connection (%d logs) with %s port %d' % (ip2host.get(pattern.id_orig_h, pattern.id_orig_h), pattern.log_count, pattern.id_resp_h, pattern.id_resp_p))

    C2_patterns.append(pattern)
print()

"""
The function that is for evaluation.
Neet to modify APT_C2.py before using it.
"""
# C2_result(es, router, C2_patterns)


"""
Collect logs of the attack we emulated.

Notes:
- ex.index:
    - logstash-victim2*: the host which the attack takes place.
    - logstash-ad*: the host which have kerberos server to get the eid 4768, 4769 for ptt detection.
"""

winlog_indices = []
for host in hosts:
    winlog_indices.append('logstash-' + host + '*')
es.index(winlog_indices)

es.should([{'event.code':'4624'},{'event.code':'10'},{'event.code':'1'},{'event.code':'4768'},{'event.code':'3'},\
          {'event.code':'4769'},{'event.code':'4770'}])

logs = es.search(clean=True)
logs.reverse()
print(len(logs), "system logs\n")

whitelist = make_lsass_whitelist(es)
whitelist = add_whitelist_0x1010(whitelist)
whitelist = remove_whitelist_malicious(whitelist)

"""
Remove whitelist log from logs which we collect from attack duration

Notes: 
= some logs in the attack which will also be remove, but they don't impact on the detection. 
    e.g. 
    10 C:\WINDOWS\system32\lsass.exe → C:\WINDOWS\system32\svchost.exe 0x1000
    10 C:\WINDOWS\system32\svchost.exe → C:\WINDOWS\system32\lsass.exe 0x1000
         10 C:\WINDOWS\system32\lsass.exe → C:\WINDOWS\system32\svchost.exe 0x1000
"""
for log in logs[:]:
    if log['event']['code'] == 10:
        if log['winlog']['event_data']['SourceImage'] == "C:\WINDOWS\system32\lsass.exe":
            if log['winlog']['event_data']['TargetImage'] in whitelist:
                logs.remove(log)
        if log['winlog']['event_data']['TargetImage'] == "C:\WINDOWS\system32\lsass.exe":
            if log['winlog']['event_data']['SourceImage'] in whitelist:
                logs.remove(log)
                


"""
Make the tree for guid parent and child order of eid 1, 3, 10, 4624

Notes:
- The tree root must be eid 1 for its the process start.

"""
trees = group_with_guid(logs)


"""
To that the eid 4768, 4769, 4770 to be the form of tree
"""
ptt_trees = ptt_detect(logs)


"""
Calculate that whether there is a eid 4769 occur while no eid 4768.

Notes:
- eid 4768 will appear 3 hours routinely.

"""
ptt_ad = print_ptt_trees(ptt_trees, 28)


"""
Detect pth and ptt malicious logs to launch alarm
"""
ptt, pth = detect(trees, ptt_ad)

print("Pass the Hash:")
print_tree(pth, C2_patterns)
print()
print("Pass the Ticket:")
print_tree(ptt, C2_patterns)
if ptt:
    First = True
    for log in ptt_ad:
        if First:
            print("(PtT)", log.eid, log.time, end="")
            First = False
        else:
            print(" →", log.eid, log.time, end="")




