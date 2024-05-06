Make sure to install the required dependencies by running the following command in your terminal:

pip install python-nmap scapy requests

To run the code, save it as a Python file (e.g., network_scanner.py), and then execute it using Python:


python network_scanner.py

The code will prompt you to enter the IP address to scan. After entering the IP address, it will perform network scanning, retrieve the MAC address and ISP provider information, and display the results.

Please note that the get_mac_address function uses the scapy library to retrieve the MAC address, which is not part of the standard Python installation. You need to install it separately using pip install scapy.

Also, the get_isp_provider function uses the requests library to make an HTTP request to an external API (ipapi.co) to retrieve the ISP provider information. Make sure you have an active internet connection when running this code.

Licenced : Bloody Hacker Official<<<<>>>>