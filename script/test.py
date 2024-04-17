import requests
import time
import random
import string
import multiprocessing
import subprocess
import json
import argparse

from kubernetes import client, config

# Kubernetes deployment configuration -> default name (check k8s/deployment.yaml)
namespace = "gossip"
label_selector = "app=gossip-service"

# Declare NODES and results as a global variable
NODES = []
results = []

# Function to execute a shell command and return its output
def execute_command(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode == 0:
        return stdout.decode('utf-8')
    else:
        raise Exception(f"Command failed: {stderr.decode('utf-8')}")

# Function to extract IP addresses from kubectl output
def get_ip_addresses(namespace, label_selector):
    # Load Kubernetes configuration, this function is not needed if your environment is already configured for Kubernetes
    # If running inside the cluster or already configured via kubectl, configuration is usually loaded automatically
    config.load_kube_config()

    # Create Kubernetes CoreV1Api object
    api = client.CoreV1Api()

    # Use the api to get a list of Pods in the specified Namespace and with the specified Label Selector
    pods = api.list_namespaced_pod(namespace, label_selector=label_selector)

    ips = []
    for pod in pods.items:
        ips.append(pod.status.pod_ip)

    return ips

# Function to extract IP addresses from kubectl output
def random_metadata_string(length=200):
    """Generate a random string of fixed length."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

# Function to send metadata update to a specific node
def send_metadata_update(node_url, metadata):
    """Send metadata update to a specific node."""
    headers = {"Content-Type": "application/json"}
    data = {"test-meta": metadata}
    requests.post(f"{node_url}/publish", headers=headers, json=data)


# Function to generate metadata updates
def metadata_update(node_list):
    while True:
        for _ in range(1500000):
            node = random.choice(node_list)  # Choose a node for update
            metadata = random_metadata_string()
            send_metadata_update(node, metadata)
            time.sleep(1/1500000 * 60)  # Spread out the 150 updates over one minute

def metadata_update_fix(node_list):
    update_count = 25000  
    for _ in range(update_count):
        node = random.choice(node_list)  
        metadata = random_metadata_string() 
        send_metadata_update(node, metadata)
        #time.sleep(0.001) 

def test_configurations():
    # Retrieve the IP addresses
    ip_addresses = get_ip_addresses(namespace, label_selector)

    for ip in ip_addresses:
        # Construct the curl command
        curl_command = f"curl http://{ip}:8000/list"
        
        try:
            curl_output = execute_command(curl_command)

            parsed_output = json.loads(curl_output)
            desired_data = parsed_output[0]
            desired_data_str = json.dumps(desired_data, indent=4)
            #print(desired_data_str)

            results.append((ip, desired_data_str))
        except Exception as e:
            print(f"Error accessing {ip}: {e}")

        print(results)    

# Function to configure the servers
def configure_servers():
    # Retrieve the IP addresses
    ip_addresses = get_ip_addresses(namespace, label_selector)

    for ip in ip_addresses:
        # Construct the curl command
        curl_command = f"curl http://{ip}:8000/list"
        
        try:
            curl_output = execute_command(curl_command)

            parsed_output = json.loads(curl_output)
            desired_data = parsed_output[0]
            desired_data_str = json.dumps(desired_data, indent=4)
            #print(desired_data_str)

            results.append((ip, desired_data_str))
        except Exception as e:
            print(f"Error accessing {ip}: {e}")

    first_node = results[0][0]

    # Iterate through results to make POST requests
    for ip, data in results:
        try:
            # Set the URL for the POST request
            url = f"http://{first_node}:8000/set"

            # Make the POST request
            response = requests.post(url, data=data, headers={'Content-Type': 'application/json'})

            # Print the response (optional)
            print(f"Response from {ip}: {response.text}")
        except Exception as e:
            print(f"Error sending POST request to {ip}: {e}")    


# Count the list length in the gossip node
def count_list_length():
    ip_addresses = get_ip_addresses(namespace, label_selector)
    for i in ip_addresses:
        url = f"http://{i}:8000/list"
        try:
            response = requests.get(url)    # Make GET request
            response.raise_for_status()     # Raise exception if invalid response

            json_data = response.json()

            ip_addresses = [item['Addr'] for item in json_data]
            ip_count = len(ip_addresses)

            print(f"IP: {i}, Nodelist size: {ip_count}")
            print("---------------------------------------")

        except requests.exceptions.RequestException as e:
            print(f"Failed to retrieve data from {i}: {e}")
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON data from {i}: {e}")

def main():
    # Parse the arguments
    parser = argparse.ArgumentParser(description="Configure the servers")   
    parser.add_argument('-t', '--test', action='store_true', help='Test parsing config', required=False)
    parser.add_argument('-c', '--configure', action='store_true', help='Configure the servers', required=False)
    parser.add_argument('-b', '--bench', action='store_true', help='Benchmakr the cluster', required=False)
    parser.add_argument('-bf', '--bench-fix', action='store_true', help='Benchmakr the cluster', required=False)
    parser.add_argument('-gl', '--get-list', action='store_true', help='Get all output list of gossip node', required=False)

    args = parser.parse_args()

    # Check the arguments
    if args.test:
        test_configurations()
    elif args.configure:
        configure_servers()
    elif args.bench:
        ip_list = get_ip_addresses(namespace, label_selector)
        # print(ip_list[0])
        # process1 = multiprocessing.Process(target=metadata_update, args=(["http://"+ip_list[0]+":8000"],))        
        
        metadata_update(["http://"+ip_list[0]+":8000"])
        # Start the processes
       # process1.start()

        # Wait for both processes to complete
        #process1.join()
    elif args.get_list:
        count_list_length()
    elif args.bench_fix:
        ip_list = get_ip_addresses(namespace, label_selector)
        # metadata_update_fix(["http://"+ip_list[0]+":8000"])
        process1 = multiprocessing.Process(target=metadata_update_fix, args=(["http://"+ip_list[0]+":8000"],))      
        #process2 = multiprocessing.Process(target=metadata_update_fix, args=(["http://"+ip_list[0]+":8000"],))
        #process3 = multiprocessing.Process(target=metadata_update_fix, args=(["http://"+ip_list[0]+":8000"],))    

        process1.start()
        #process2.start()
        #process3.start()
        
        process1.join()
        #process2.join()
        #process3.join()
    else:
        print("No arguments given")

if __name__ == "__main__":
    main()
