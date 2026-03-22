import json
import os

def get_all_cves():
    path = os.path.join(os.path.dirname(__file__), '..', 'cve_data', 'cves.json')
    with open(path, 'r') as f:
        data = json.load(f)
    return data['cves']

def get_cve_by_id(cve_id):
    cves = get_all_cves()
    for cve in cves:
        if cve['id'] == cve_id:
            return cve
    return None
