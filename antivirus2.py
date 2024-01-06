import os
import requests
import time

def scan_file_with_virustotal(file_path, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}

    try:
        with open(file_path, 'rb') as file:
            files = {'file': (file_path, file)}
            response = requests.post(url, files=files, params=params)

        response.raise_for_status()

        if response.status_code == 200:
            json_response = response.json()
            json_response = json_response.get('resource')
            if json_response:
                return json_response
    except Exception as e:
        print(f"Error scanning file {file_path}: {str(e)}")

    return None

def get_scan_report(api_key, json_response):
    url = f'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': json_response}

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()

        if response.status_code == 200:
            json_response = response.json()
            positives = json_response.get('positives', 0)
            if positives > 0:
                return f"File is flagged as malicious by {positives} out of {json_response.get('total', 0)} scanners."
            else:
                return "File does not have viruses."
    except Exception as e:
        print(f"Error getting scan report for resource {json_response}: {str(e)}")

    return "Error retrieving scan report."

def scan_files_in_directory(directory_path, api_key):
    for root, dirs, files in os.walk(directory_path):
        for name in files:
            file_path = os.path.join(root, name)
            print("wait 10 seconds...")
            print(f"Scanning file: {file_path} , {name}")

            resource = scan_file_with_virustotal(file_path, api_key)

            if resource:
                report = get_scan_report(api_key, resource)
                print(report)
            else:
                print("Error submitting file for scanning.")
            time.sleep(10)
    print("The scan is finished")

api_key = '463677ffe69693e51565e09113584eb0eda540400e074967eb8707d4645c15df'
directory_path = input("Enter the path of the directory to scan: ")
scan_files_in_directory(directory_path, api_key)
