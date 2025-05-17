
## Installation

**1.** If you are a Debian based linux user then

```bash
git clone https://github.com/Fuwad9096/Hybrid_IDS.git
```

**2.** Create a virtual environment in the same directory where `Hybrid_IDS` is located.

```bash
python3 -m venv venv
source venv/bin/activate
```

**3.** Run the requirements.txt file. It will install the required dependencies.

```bash
pip install -r requirements.txt
```

**4.** Change the `user` and `password` of the `alert_system.py` and `decrypt_alerts.py` file according to your `MySQL` username and password.

```bash
# --- Your Database Configuration ---
DB_CONFIG = {
    'host': 'localhost',
    'user': 'your_user',
    'password': 'your_password',
    'database': 'cryptosafedb'
}
```

**5.** You need to change the value assigned to the network interface that is set in the `IntrusionDetectionSystem` class's `__init__` method in `hybrid_ids.py` according to your network interface. It can be `eth0` or `wlan0` according to what network interface you are using.

```bash
class IntrusionDetectionSystem:
    def __init__(self, interface="eth0"):
        # ... other initializations ...
        self.interface = interface  # You might need to change this
        # ...
```

To change the interface, modify the line where `self.interface` is assigned.  For example, if your network interface is `wlan0`, you would change it to:

```bash
class IntrusionDetectionSystem:
    def __init__(self, interface="wlan0"):
        # ... other initializations ...
        self.interface = interface  # Now set to wlan0
        # ...
```

**Important:** The `interface` parameter in the `__init__` method also allows you to specify the interface when you create an instance of the `IntrusionDetectionSystem` class.  This is actually the preferred way to do it.

Here's how you can do that when you run the code:

```bash
if __name__ == "__main__":
    ids = IntrusionDetectionSystem(interface="wlan0")  # Specify interface here
    ids.start()
```

By default it is set to `eth0`

**6.** Run the `hybrid_ids.py` with `sudo`

```bash
sudo python3 hybrid_ids.py
```

**7.** In `decrypt_alerts.py` replace the placeholder encryption key with the actual key that is printed when `hybrid_ids.py` is run.

```bash
# --- The Encryption Key (You MUST replace this with the key printed by hybrid_ids.py) ---
ENCRYPTION_KEY = b'YOUR_ENCRYPTION_KEY_HERE'
```

Make sure to copy the key from the output of `hybrid_ids.py` and paste it here keeping the `b'` prefix.





