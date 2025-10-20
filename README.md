# Medical Packet Analyzer (MPA)

**Author:** Mohamed Habak
**Project Type:** SOC-relevant Medical Packet Analyzer

---

## Video Demo

[Link to demo video](https://youtu.be/U4LKQ5sffMs)

---

## Description

The **Medical Packet Analyzer (MPA)** is a Flask-based web application designed to analyze, visualize, and report network traffic data from PCAP and PCAPNG files, with a particular focus on **medical network security** and **HL7 protocol analysis**.

It simulates a **Security Operations Center (SOC)** workflow, allowing users to upload and inspect network captures, detect anomalies, and monitor communication patterns in healthcare or secure network environments.

It combines **cybersecurity concepts** (packet forensics, anomaly detection, incident analysis) with **healthcare-specific awareness** (HL7 traffic, PHI protection, data integrity).

---

## What It Does

* Accepts `.pcap` and `.pcapng` uploads via a Flask web form.
* Uses **PyShark** to parse PCAP files and extract metadata such as IPs, ports, protocols, timestamps, and payload snippets.
* Runs a set of detection rules focused on HL7-related anomalies:

  * **Replay attack detection** – identifies duplicate HL7 messages.
  * **Data exfiltration detection** – detects HL7 messages sent to unknown or external IPs.
  * **Unencrypted HL7 detection** – flags HL7 markers visible without TLS/SSL encryption.
  * **Traffic spike detection** – identifies sudden bursts of HL7 messages per minute.
* Differentiates between **internal and external IP addresses**.
* Displays an interactive dashboard with:

  * Protocol statistics
  * Top talkers
  * Packet timestamps
  * Security alerts and anomaly summaries
* Stores parsed results as JSON to avoid reprocessing the same file multiple times.

---

## File Structure

* **app.py** – Main Flask application; handles routes, file uploads, packet parsing, and rendering.
* **templates/** – HTML templates:

  * `index.html`: Upload page and user instructions.
  * `dashboard.html`: Displays parsed PCAP data, alerts, and summaries.
  * `packet.html`: Displays individual packet details for flagged packets.
* **static/** – Contains front-end assets (CSS).
* **demo_pcaps/** – Example capture files for demonstration.

  * `all_alerts.pcap`: Combined capture containing samples of all traffic scenarios used in testing.
  * `no_alerts.pcap`: Normal baseline network activity with no anomalies.
  * `data_exfiltration.pcap`: Simulated data transfer from an internal host to an external destination.
  * `unencrypted_hl7.pcap`: Example of unencrypted HL7 communication between medical devices.
  * `traffic_spike.pcap`: Short capture showing a burst of network activity for load analysis.
  * `replay_attack.pcap`: Simulated replay of previously captured packets between devices.
* **README.md** – Project documentation (this file).

---

## How to Run

1. **Install dependencies:**
   Make sure you have Python 3 and Wireshark (`tshark`) installed on your system.

   ```bash
   pip install -r requirements.txt
   ```

   *(This installs Flask, Werkzeug, and PyShark automatically.)*

2. **Run the Flask server:**

   ```bash
   flask run
   ```

   *(Ensure you are in the project’s root directory where `app.py` is located.)*

3. **Open your browser:**

   ```
   http://127.0.0.1:5000
   ```

4. **Upload a PCAP or PCAPNG file** — or use one of the example files from the **`demo_pcaps/`** folder to test the application.

---

## Requirements

* Python 3.10+
* Flask
* PyShark
* Wireshark (Tshark backend)

---

## Design Choices

* **Flask** was chosen for its simplicity and clear modular structure.
* **PyShark** was selected over Scapy due to its higher-level interface for parsing PCAP files.
* The **dashboard layout** was designed for clarity and ease of navigation, separating upload, summary, and detailed views.
* Security measures include:

  * File size limits and extension validation.
  * Local-only file handling.
  * No decryption or interception capabilities.

---

## Why Decryption Was Not Included (Technical, Ethical, and Legal Reasons)

This program only analyzes **unencrypted HL7 data** that can be clearly read inside a PCAP file. It **does not and cannot** decrypt secure (TLS or HTTPS) traffic. Modern encryption (like TLS with Diffie–Hellman keys) makes it impossible to decrypt data just from a capture file.

Decrypting encrypted traffic would require access to session keys, the server’s private key, or a trusted proxy that terminates TLS — all of which are unavailable or inappropriate for this educational project.

There are three reasons decryption was deliberately excluded:

* **Technical:** Modern TLS uses temporary keys that prevent passive decryption.
* **Ethical:** Real medical data may contain sensitive personal information (PHI).
* **Legal:** Unauthorized decryption of patient data could violate data protection laws such as HIPAA or GDPR equivalents.

Therefore, MPA is designed only to handle **safe, anonymized, or synthetic data**, and automatically flags any readable HL7 payload as unencrypted. This is expected behavior, not an error.

---

## Why the `unencrypted-hl7` Alert Triggers Frequently

This rule fires when:

1. The payload contains HL7 identifiers (e.g., `MSH|`, `PID|`, `OBR|`).
2. The packet lacks TLS/SSL layers.

Because the project does not perform decryption, any visible HL7 content will trigger this alert. It correctly signals plaintext HL7 presence but not necessarily insecure production configurations.

**Edge cases:**

* Captures taken before TLS encryption may show plaintext even in secure systems.
* Captures after TLS termination may show only encrypted data.

In a real commercial-grade implementation, decrypted packets would pass through additional inspection logic. However, since MPA does not decrypt, the **unencrypted HL7 alert will almost always trigger** when medical identifiers are visible in test captures. This behavior is intentional for transparency and safety.

---

## Challenges

* Making sure large PCAP files could be processed smoothly without the web app freezing.
* Fixing a problem where PyShark (the packet reader) needed an **asyncio** event loop, but none existed in the thread running the parser.
  (The solution was to create or get an event loop inside `pcap_parser.py` before calling PyShark, so it could read packets correctly.)
* Designing the dashboard to stay simple while still showing useful technical information.
* Keeping the project clear and educational while still following real cybersecurity practices.

---

## Acknowledgements

During development, I used **ChatGPT** as a study and assistance tool to clarify Flask and Python concepts, generate initial code skeletons, and improve documentation comments.
All final logic, implementation, debugging, and testing decisions were my own.

---

## License

This project was created as part of **CS50x's Final Project** and is open for **educational use only**.
