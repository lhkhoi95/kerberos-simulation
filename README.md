# A Simulation of Kerberos Authentication

### 1: Retrieve the IP address

To find the IP address on a Mac:

- Open the Terminal application.
- Type "ifconfig" and press Enter.
- Look for the line starting with "inet ". Your IP address will be listed next to it.

To find the IP address on Windows:

- Open the Command Prompt by typing "cmd" in the Windows search bar and clicking on the "Command Prompt" app.
- In the Command Prompt, type "ipconfig" and press Enter.
- Look for the "IPv4 Address" under the "Ethernet adapter" or "Wi-Fi" section, depending on how you are connected to the network.
- The IP address will be displayed next to "IPv4 Address", and will usually be a set of four numbers separated by periods (e.g. 192.168.1.100).

### 2: Set the SERVER_ADDRESS (line #7 in helpers.py) to the IP address you obtained from step 1.

    SERVER_ADDRESS = 'Your IP Address Goes Here'

### 3: Run the code in VScode

- Open two terminals, one for the client and one for the server. Arrange them side by side.
- In the server terminal, run the server by typing:
  python server.py
- In the client terminal, run the client by typing:
  python client.py
- Enter the username and password when prompted:
  username: team4
  password: letmein
- Press Enter to send requests between the client and server.
