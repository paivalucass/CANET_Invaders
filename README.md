# CAN Invaders

A IDS (Intrusion Detection System) software for CAN bus malicious attacks.

---
### How to run

On terminal:

1. Clone the repository:
    ```bash
    git clone https://github.com/paivalucass/CAN_Invaders.git
    ```

2. Install the packages:
    ```bash
    pip install -e
    ```

3. Install the repository dependencies:
    ```bash
    pip install -r requirements.txt
    ```

---

### Usage

The repository has three main features:

1. Attack the CAN bus in three possible ways:
   1. fuzzing attack
   2. impersonation attack
   3. falsifying attack
   4. doS attack

2. Generate a model from recorded CAN bus attacks

3. Run an IDS system using a model provided when connected to a CAN bus

Choose the params you want to change when running every script on an active CAN Bus. 
We recommed you make use of the can-utils library for recording the CAN bus traffic to be able to make use of the full potential of this repository.

### Virtual Interface using CAN-Utils

For simnplicity, you can use a virtual interface to run this software. With can-utils installed on your machine run:

    ```bash
    sudo modprobe vcan
    sudo ip link add dev vcan0 type vcan
    sudo ip link set up vcan0´
    ```