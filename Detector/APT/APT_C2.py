import json
from scipy import stats
import numpy as np
import datetime as dt
import elk as elk
import re
from sklearn.metrics import classification_report, plot_confusion_matrix, confusion_matrix
from sklearn.utils.multiclass import unique_labels
import matplotlib.pyplot as plt



class ConnPattern:
    def __init__(self, id_orig_h, id_resp_h, id_resp_p, service):
        self.id_orig_h = id_orig_h 
        self.id_resp_h = id_resp_h  
        self.id_resp_p = id_resp_p
        self.service = service  

        self.log_count = 0
        self.log_list = []
        self.log_itvl = []
        self.log_itvl_avg = 0
        self.log_itvl_var = 0
        
    def add(self, data):
        self.log_list.append({
                            'timestamp': data['@timestamp']
                            })
        self.log_count += 1
        self.calculate()

    def calculate(self):
        intervals = []
        for i in range(len(self.log_list) - 1):
            time_diff = parse_timestamp(self.log_list[i+1]['timestamp']) - parse_timestamp(self.log_list[i]['timestamp'])
            intervals.append(time_diff.total_seconds())
        if len(intervals) > 1:
            z = np.abs(stats.zscore(intervals))
            intervals = [ intervals[i] for i in range(len(intervals))  if z[i] <= 2.5 ]
        if len(intervals) > 0:
            self.log_itvl_var = np.var(intervals)
            self.log_itvl_avg = np.mean(intervals)
        self.log_itvl = intervals

        
def parse_timestamp(time_str):
    date_time_obj = dt.datetime.strptime(time_str, '%Y-%m-%dT%H:%M:%S.%fZ')
    return date_time_obj


"""
Calculate the time intervals between each of the same connection, and remove the outliers.
"""

def C2_detect(es, host):
    ret_patterns = []
    host_index = 'logstash-' + host + '.zeek-conn*'

    es.index(host_index)
    
    data_list = es.search(clean=True)
    data_list.reverse()
    print(len(data_list), "connection logs\n")
    for data in data_list:
        for pattern in ret_patterns:
            if data["id_orig_h"] == pattern.id_orig_h and data["id_resp_h"] == pattern.id_resp_h and data["id_resp_p"] == pattern.id_resp_p \
            and data["service"] == pattern.service:
                pattern.add(data)
                break
        else:
            new_pattern = ConnPattern(data["id_orig_h"], data["id_resp_h"], data["id_resp_p"], data["service"])
            new_pattern.add(data)
            ret_patterns.append(new_pattern)
    return ret_patterns


"""
This function prints and plots the confusion matrix.
Normalization can be applied by setting `normalize=True`.
"""

def plot_confusion_matrix(y_true, y_pred, classes,
                          normalize=False,
                          title=None,
                          cmap=plt.cm.Blues):
    if not title:
        if normalize:
            title = 'Normalized confusion matrix'
        else:
            title = 'Confusion matrix, without normalization'

    # Compute confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    # Only use the labels that appear in the data
    #classes = classes[unique_labels(y_true, y_pred)]
    if normalize:
        cm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
        print("Normalized confusion matrix")
    else:
        print('Confusion matrix, without normalization')
    print(cm)
    

"""
The function that is for evaluation.
"""

def C2_result(es, host, C2_patterns):
    host_index = 'logstash-' + host + '.zeek-conn*'
    es.index(host_index)
    
    data_list = es.search(clean=True)
    data_list.reverse()
    # Modify this line to fit your answer
    Y_ans = [ 1 if (data["id_resp_h"], data["id_resp_p"]) == ("140.113.194.82", 443) else 0 for data in data_list]
    Y_pred = []
    for data in data_list:
        for pattern in C2_patterns:
            if (data["id_orig_h"], data["id_resp_h"], data["id_resp_p"]) == (pattern.id_orig_h, pattern.id_resp_h, pattern.id_resp_p):
                Y_pred.append(1)
                break
        else:
            Y_pred.append(0)
               
    print(classification_report(Y_ans, Y_pred))
    plot_confusion_matrix(Y_ans, Y_pred, classes=np.array([0, 1]), cmap=plt.cm.Blues)
    plt.show()
    
   




    