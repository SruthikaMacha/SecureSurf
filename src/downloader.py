# blocks files before downloading

import os

def load_threat_lists():
    ad_domains = set()
    unsafe_urls = set()
    
    # Go up one folder from 'src' to find the 'data' folder
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    try:
        with open(os.path.join(base_dir, 'data', 'ads_hosts.txt'), 'r') as f:
            for line in f:
                if line.strip(): ad_domains.add(line.strip())
    except FileNotFoundError:
        print("Ad list not found. Make sure ads_hosts.txt is in the data folder.")
        
    try:
        with open(os.path.join(base_dir, 'data', 'unsafe_urls.txt'), 'r') as f:
            for line in f:
                if line.strip(): unsafe_urls.add(line.strip())
    except FileNotFoundError:
        print("Unsafe list not found. Make sure unsafe_urls.txt is in the data folder.")
        
    return ad_domains, unsafe_urls