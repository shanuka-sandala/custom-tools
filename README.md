# Custom-Tools
This repository contains tools I have created to simplify my daily tasks. Some of these tools might be useful to you as well. With a few modifications, you can customize the code to suit your specific needs. These all are made using Python.

# 1. Malicious IP Processor & Blacklist Management Tool
Malicious IP Processor and Blacklist Management Tools are created for manage the PaloAlto EDL file in the server. Here are the functionalities of the mentioned Tools;

This tool is designed to upload the IP list received from the SOC team for blocking. We need to update the EDL text file with these IPs. The SOC provides the IPs in an Excel sheet with their specific format, and we are required to process the data while ensuring that any private IPs are removed.

The Malicious IP Processor tool includes the following functions:

- Identify and remove any private IPs.
- Process the IP list into a standardized format.
- Convert the Excel file into a text file.
- Upload the file and display its checksum.

Blacklist Managemnt Tool used to manage the External Dynamic List (EDL), which contains the IP addresses. The tool has features such as;

- It can maintain an IP limit of 50,000. If the limit is exceeded when adding new IPs, the oldest entries will be removed, making a record of it.
- It does not remove domains from the list—only IP addresses—ensuring effective list management.
-	It can remove duplicate IPs, if any exist.
-	It supports Undo/Redo functionality for rollback purposes.

# 2. File Transfer Tool
This tool was created for general file-sharing purposes, inspired by the tool mentioned above.

Here are the features of the tool:

- Upload and download files with a single executable, with a progress bar.
- Display the checksum of uploaded and downloaded files.
- Easily share files—just send the .exe version to a friend and share the download URL.
