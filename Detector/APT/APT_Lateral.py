import json
import numpy as np
import datetime as dt
import elk as elk
import re

"""
Make the lsass whitelist.

Notes:
- the es.time should choice a right time duration, so as not to miss some normal process logs.
- MsMpEng is the process that will have the EID 10 GrantedAccess 0x1010, but its name will vary with its version

"""
def make_lsass_whitelist(es):
    es.time('now-7d','now')
    es.should([{'event.code':'10'},{'TargetImage':"C:\WINDOWS\system32\lsass.exe"}])
    log_targetImage = es.search(clean=True)

    es.should([{'event.code':'10'},{'SourceImage':"C:\WINDOWS\system32\lsass.exe"}])
    log_sourceImage = es.search(clean=True)
    
    whitelist = set()

    for log in log_targetImage:
        whitelist.add(log['winlog']['event_data']['SourceImage'])

    for log in log_sourceImage:
        whitelist.add(log['winlog']['event_data']['TargetImage'])

    return whitelist

def add_whitelist_0x1010(whitelist):
    whitelist.add("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2104.14-0\\MsMpEng.exe")
    whitelist.add("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2104.10-0\\MsMpEng.exe")
    whitelist.add("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2103.7-0\\MsMpEng.exe")
    
    return whitelist


# Not to include the mimikatz in the whitelist
def remove_whitelist_malicious(whitelist):
    if 'C:\\Users\\user\\Desktop\\mimikatz.exe' in whitelist:
        whitelist.remove('C:\\Users\\user\\Desktop\\mimikatz.exe')
    if 'C:\\Users\\user\\Downloads\\mimikatz.exe' in whitelist:
        whitelist.remove('C:\\Users\\user\\Downloads\\mimikatz.exe')
    if "C:\\Users\\user\\Desktop\\mimikatz\\mimikatz.exe" in whitelist:
        whitelist.remove("C:\\Users\\user\\Desktop\\mimikatz\\mimikatz.exe")
    if 'C:\\WINDOWS\\system32\\PsExec.exe' in whitelist:
        whitelist.remove('C:\\WINDOWS\\system32\\PsExec.exe')
    
    return whitelist


"""
treeNode for the guid parent and child order
struct for ptt detection easily to do

"""
class struct:
    #__slots__ = []
    def __init__(self,**data):
        self.__dict__.update(data)
        self.next = None
        
class treeNode:
    def __init__(self, SourceProcessGUID):
        self.root = True
        self.EID = None
        self.SourceProcessGUID = SourceProcessGUID
        self.ChildProcessGUID = None
        self.SourceImage = None
        self.ChildImage = None
        self.GrantedAccess = None
        self.LogonId = None
        self.SubjectLogonId = None
        self.TargetLogonId = None
        self.LogonType = None
        self.time = None
        self.Parent = None
        
        self.Children = []
        
        ## network
        self.Protocol = None
        self.DestinationIp = None
        self.SourcePort = None
        self.DestinationPort = None
        self.SourceIp = None

"""
Make the tree for guid parent and child order of eid 1, 3, 10, 4624

Notes:
- The tree root must be eid 1 for its the process start.

"""

def group_with_guid(logs):
    first = True
    trees = []

    for log in logs:
        c = False
        trees.reverse()
        for t in trees:
            if log['event']['code'] == 10:
                if log['winlog']['event_data']['SourceProcessGUID'] == t.ChildProcessGUID \
                    or log['winlog']['event_data']['TargetProcessGUID'] == t.ChildProcessGUID:
                    tree = treeNode(log['winlog']['event_data']['SourceProcessGUID'])
                    tree.EID = 10
                    tree.ChildProcessGUID = log['winlog']['event_data']['TargetProcessGUID']
                    tree.SourceImage = log['winlog']['event_data']['SourceImage']
                    tree.ChildImage = log['winlog']['event_data']['TargetImage']
                    tree.GrantedAccess = log['winlog']['event_data']['GrantedAccess']
                    tree.time = log['event']['created']
                    tree.root = False
                    tree.Parent = t
                    t.Children.append(tree)
                    trees.reverse()
                    trees.append(tree)
                    c = True
                    break
            elif log['event']['code'] == 1 and log['winlog']['event_data']['ParentProcessGuid'] == t.ChildProcessGUID:
                tree = treeNode(log['winlog']['event_data']['ParentProcessGuid'])
                tree.EID = 1
                tree.ChildProcessGUID = log['winlog']['event_data']['ProcessGuid']
                tree.SourceImage = log['winlog']['event_data']['ParentImage']
                tree.ChildImage = log['winlog']['event_data']['Image']
                tree.LogonId = log['winlog']['event_data']['LogonId']
                tree.time = log['event']['created']
                tree.root = False
                t.Children.append(tree)
                trees.reverse()
                trees.append(tree)
                c = True
                break
                
            ## for the logon type 9
            elif log['event']['code'] == 4624 and log['winlog']['event_data']['SubjectLogonId'] == t.LogonId:
                tree = treeNode('{4624}')
                tree.root = False
                tree.EID = 4624
                tree.SubjectLogonId = log['winlog']['event_data']['SubjectLogonId']
                tree.TargetLogonId = log['winlog']['event_data']['TargetLogonId']
                tree.LogonType = log['winlog']['event_data']['LogonType']
                tree.time = log['event']['created']
                t.Children.append(tree)
                trees.reverse()
                trees.append(tree)
                c = True
                break
                
            ## for the network destination detection
            elif log['event']['code'] == 3 and log['winlog']['event_data']['ProcessGuid'] == t.ChildProcessGUID:
                tree = treeNode(log['winlog']['event_data']['ProcessGuid'])
                tree.EID = 3
                tree.Image = log['winlog']['event_data']['Image']
                tree.Protocol = log['winlog']['event_data']['Protocol']
                tree.DestinationIp = log['winlog']['event_data']['DestinationIp']
                tree.SourcePort = log['winlog']['event_data']['SourcePort']
                tree.DestinationPort = log['winlog']['event_data']['DestinationPort']
                tree.SourceIp = log['winlog']['event_data']['SourceIp']
                tree.root = False
                t.Children.append(tree)
                trees.reverse()
                trees.append(tree)
                c = True
                break

        if c:
            continue
        trees.reverse()

        if log['event']['code'] == 1:
            tree = treeNode(log['winlog']['event_data']['ParentProcessGuid'])
            tree.EID = 1
            tree.ChildProcessGUID = log['winlog']['event_data']['ProcessGuid']
            tree.SourceImage = log['winlog']['event_data']['ParentImage']
            tree.ChildImage = log['winlog']['event_data']['Image']
            tree.LogonId = log['winlog']['event_data']['LogonId']
            tree.time = log['event']['created']
            trees.append(tree)
    
    return trees


"""
To that the eid 4768, 4769, 4770 to be the form of tree
"""

def ptt_detect(logs):
    ptt_detect = None
    current = None
    First = True
    
    for log in logs:
        if First:
            if log['event']['code'] == 4768 or log['event']['code'] == 4769 or log['event']['code'] == 4770:
                node = struct()
                node.eid = log['event']['code']
                node.time = log['event']['created']
                node.next = None
                current = node
                ptt_detect = current
                First = False
        else:
            if log['event']['code'] == 4768 or log['event']['code'] == 4769 or log['event']['code'] == 4770:
                node = struct()
                node.eid = log['event']['code']
                node.time = log['event']['created']
                node.next = None
                current.next = node
                current = current.next

    return ptt_detect


"""
Calculate that whether there is a eid 4769 occur while no eid 4768.

Notes:
- eid 4768 will appear 3 hours routinely.

"""

def print_ptt_trees(trees, time_4768):    
    if_4768 = None
    ptt_ad = []
    current = trees
    First = True
    while current != None:
        if current.eid == 4768:
            time_4768 = int(current.time[current.time.find('T')+1:current.time.find('T')+3])
        elif current.eid == 4769:
            if abs(int(current.time[current.time.find('T')+1:current.time.find('T')+3]) - time_4768) > 3:
                ptt_ad.append(current)
        current = current.next

    return ptt_ad



"""
Print the tree of eid 1, 3, 10, 4624
"""

def print_tree(trees, C2_patterns):
        
    def print_child(tree, i):
        for t in tree:
                if t.EID == 4624:
                    if t.LogonType == "9":
                        print('    '*i, "(PtH) Event", t.EID, end=" ")
                    else:
                        print('    '*i, "Event", t.EID, end=" ")
                    print("LogonType:", t.LogonType)
                    continue
                elif t.EID == 3:
                    for C2_pattern in C2_patterns:
                        if t.DestinationIp == C2_pattern.id_resp_h and int(t.DestinationPort) == C2_pattern.id_resp_p:
                            print('    '*i, "(C&C) Event", t.EID, end=" ")
                            break
                    else:
                        print('    '*i, "Event", t.EID, end=" ")

                    print("Destination:", t.DestinationIp, "Port:", t.DestinationPort)
                    continue
                if t.EID == 10:
                    if t.GrantedAccess == "0x1010":
                        print('    '*i, "(PtH/PtT) Event", t.EID, t.SourceImage,'→', t.ChildImage, end=" ")
                    else:
                        print('    '*i, "Event", t.EID, t.SourceImage,'→', t.ChildImage, end=" ")
                    print(t.GrantedAccess)
                else:
                    print('    '*i, "Event", t.EID, t.SourceImage,'→', t.ChildImage, end=" ")
                    print()
                print_child(t.Children, i+1)

    for tree in trees:
        if tree.root:
            print("Event", tree.EID, tree.SourceImage, '→', tree.ChildImage, end=" ")
#             print(tree.EID, tree.SourceImage, '→', tree.ChildImage, end=" ")
    #         print(tree.EID, tree.SourceImage, tree.SourceProcessGUID, '→', tree.ChildImage, tree.ChildProcessGUID, end=" ")
            if tree.EID == 10:
                print(tree.GrantedAccess)
            else:
                print()
            print_child(tree.Children, 1)
            print()
            
            
            
"""
Detect pth and ptt malicious logs to launch alarm
"""
    
def detect(trees, ptt_ad):
    
    def child_detect(tree, if_logontype9, if_0x1010):
        for t in tree:
            if t.EID == 4624:
                if t.LogonType == "9":
                    if_logontype9 = True
    #                     print("if_logontype9:", if_logontype9, " if_0x1010:", if_0x1010)

            elif t.EID == 10:
                if t.GrantedAccess == "0x1010":
                    if_0x1010 = True
    #                     print("if_logontype9:", if_logontype9, " if_0x1010:", if_0x1010)

            if_logontype9, if_0x1010 = child_detect(t.Children, if_logontype9, if_0x1010)
        
        return if_logontype9, if_0x1010

    ptt = []
    pth = []
    current = None
    
    if_logontype9 = False
    if_0x1010 = False
    
    for tree in trees:
        malicious = None
        if_logontype9 = False
        if_0x1010 = False
        if tree.root:
            current = tree

            if_logontype9, if_0x1010 = child_detect(tree.Children, if_logontype9, if_0x1010)
        
#             print("if_logontype9:", if_logontype9, " if_0x1010:", if_0x1010)
            if if_logontype9 and if_0x1010:
                pth.append(current)
            elif if_0x1010 and ptt_ad:
                ptt.append(current)
    
    return ptt, pth