import requests
import time
import random
import string

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

def main():
    end_time = time.time() + 15*60  # Set end time to 15 minutes from now

    while time.time() < end_time:
        for _ in range(150000):
            node = random.choice(NODES)  # Choose a random node for each update
            metadata = random_metadata_string()
            send_metadata_update(node, metadata)
            time.sleep(1/150000 * 60)  # Spread out the 150 updates over one minute

if __name__ == "__main__":
    main()
