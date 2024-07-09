# CANET Invaders

A IDS (Intrusion Detection System) software for CAN and Automotive Ethernet malicious attacks.

---
### How to run

On terminal:

**Attention! It may be interesting to create an enviroment before installing the dependencies**

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

2. Generate a model from recorded CAN bus attacks or Ethernet attacks.

3. Run an IDS system using a model provided when connected to a CAN bus or Ethernet interface.  

We recommed you make use of the can-utils library for recording the CAN bus traffic to be able to make use of the full potential of this repository.

---

### Virtual Interface using CAN-Utils

For simplicity, you can use a virtual interface to run this CAN software. With can-utils installed on your machine run:

    ```
    sudo modprobe vcan
    sudo ip link add dev vcan0 type vcan
    sudo ip link set up vcan0´
    ```

### Virtual Interface using Ethernet

Also, for simplicity, you can use a virtual Ethernet interface to use this software on. For that, run the following commands:

    ```
    sudo modporobe dummy 
    sudo ip link add eth10 type dummy
    sudo ip link set eth10 up 
    ```

To see the packages run:

    ```
    sudo tcpdump -i eth10
    ```