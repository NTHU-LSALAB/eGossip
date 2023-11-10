import requests
import time
import random
import string
import multiprocessing

NODES_1 = ["http://192.168.3.11:8000"]
NODES_2 = ["http://192.168.3.12:8000"]
NODES_3 = ["http://192.168.3.13:8000"]

NODES = [
    "http://192.168.3.11:8000",
    "http://192.168.3.12:8000",
    "http://192.168.3.13:8000",
    "http://192.168.3.14:8000",
    "http://192.168.3.15:8000",
    "http://192.168.3.16:8000",
    "http://192.168.3.17:8000",
    "http://192.168.3.18:8000",
    "http://192.168.3.19:8000",
    "http://192.168.3.20:8000"
]



def random_metadata_string(length=200):
    """Generate a random string of fixed length."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def send_metadata_update(node_url, metadata):
    """Send metadata update to a specific node."""
    headers = {"Content-Type": "application/json"}
    data = {"test-meta": metadata}
    requests.post(f"{node_url}/publish", headers=headers, json=data)

def metadata_update(node_list):
    end_time = time.time() + 10*60  # Set end time to 15 minutes from now

    while time.time() < end_time:
        for _ in range(1500000000):
            node = random.choice(node_list)  # Choose a node for update
            metadata = random_metadata_string()
            send_metadata_update(node, metadata)
            time.sleep(1/1500000000 * 60)  # Spread out the 150 updates over one minute

def main():
    # Create two subprocesses for the two nodes
    process1 = multiprocessing.Process(target=metadata_update, args=(NODES_1,))
    #process2 = multiprocessing.Process(target=metadata_update, args=(NODES_2,))
    #process3 = multiprocessing.Process(target=metadata_update, args=(NODES_3,))

    # Start the processes
    process1.start()
    #process2.start()
    #process3.start()

    # Wait for both processes to complete
    process1.join()
    #process2.join()
    #process3.join()

if __name__ == "__main__":
    main()
