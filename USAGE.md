📦 Usage
python3 analyze_pcap.py <yourfile.pcap>


If no filename is given, the script defaults to WebServer.pcap.

Example:

python3 analyze_pcap.py traffic.pcap

🔑 XOR Key

The script uses a static XOR key for decoding:

KEY = b"5eCuR3"


Modify this in the script if your capture uses a different key.

🧠 How It Works

Reads packets from the .pcap file

Groups TCP streams (flows) based on IP/port tuples

Searches for Base64 strings and auth= or data= parameters

Decodes Base64, reverses the bytes, and XORs with the key

Prints all candidate decoded data in a readable form

🖨️ Example Output
FLOW: ('192.168.1.10', '192.168.1.20', 52314, 80) size 2456
 auth/data: ['auth=I0BCQipKGVA=']
 candidate: I0BCQipKGVA=
  decoded: flag{W3b5h3ll_und3r_th3_c0rp_d0m41n}

📂 Repository Structure
pcap-analyzer/
├── analyze_pcap.py
├── README.md
└── .gitignore

🧑‍💻 Author

Felsi Francis K
Ethical Hacker & Software Developer
📧 felsifrancis@gmail.com

🔗 LinkedIn

⚖️ License

This project is licensed under the MIT License — free to use, modify, and distribute.
