import json
import socket
import sys
from collections import defaultdict
from collections import OrderedDict
import time
import threading
for i in range(300):
    keys_to_process = ["HH_layer_key_1", "HH_layer_key_2", "HH_layer_key_3"]
    all_data = defaultdict(int)
    for key_table in keys_to_process:
        ID_table = getattr(bfrt.heavyhitter.pipe.Ingress, key_table)
        ID_text = ID_table.dump(json=True, from_hw=True)
        IDs = json.loads(ID_text)
        for entry in IDs:
            key = entry['data']['Ingress.{}.key'.format(key_table)][1]
            value = entry['data']['Ingress.{}.count'.format(key_table)][1]
            if key in all_data:
                all_data[key] += value
            else:
                all_data[key] = value
    sorted_data = OrderedDict(sorted(all_data.items(),reverse=True, key=lambda x: x[1]))
    top_20_data = dict(list(sorted_data.items())[:100])
    json_data = json.dumps(top_20_data)
    host = '192.168.13.34'
    port = 12345
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(json_data.encode('utf-8'))
    print('Done #{} Update'.format(i))
    time.sleep(1)