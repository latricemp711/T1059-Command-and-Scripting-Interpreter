# T1059-Command-and-Scripting-Interpreter
In this lab project, you will simulate a basic script execution attack by running an Atomic Red script called "AutoIt Script Execution" in your Azure Windows VM. “Script execution attacks” are when a bad actor infects your endpoint with malware that uses a “script interpreter” (in this case, AutoIt.exe) to automatically launch malicious programs.

## Steps Taken

### 1. Searched the `Indicators` 
Steps Taken 
A bad actor successfully launched an atomic script on computer hostname Threathunting-LMP on October 31st at 10:30am. Incident and Alerts trigger an alert through Microsoft defender. One alert went off Multi-stage incident involving Execution & Defense. As well as Intenet Explorer is being used to install AutoIt.exe That is the indicator of compromises. It showed that AutoIt3.exe was file was created four times. The InitiatingProcessFileName is autoit-v3-setup.exe. We also see that the RequestAccountName is latricemp711. Code is below:

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threathunting-l"
| where FileName has "AutoIt3"  and FileName endswith ".exe"
| where ActionType == "FileCreated"
| where InitiatingProcessFileName contains "autoit"
```
<img width="2505" height="1350" alt="T1059_LAUNCHOFSCRIPT_CALC_001" src="https://github.com/user-attachments/assets/b9b728f5-4cdc-491d-8eee-61db5de1c62b" />

---

### 2. Searched the `Log Timelines` Table

 Microsoft Defender Logs Timelines- Upon analyzing Microsoft Defender timeline  that stands out for me is alert timeline at 10:28:17 remote execution start process of this specified command line ""powershell.exe" & {Start-Process -FilePath \""C:\Program Files (x86)\AutoIt3\AutoIt3.exe\"" -ArgumentList \""C:\Users\latricemp711\atomic-red-team\atomics\\T1059\src\calc.au3\""}  " It shows the PE metadata powershell.exe . The user Threathungting-l\latricemp711 

<img width="1983" height="298" alt="T1059_IOC_002" src="https://github.com/user-attachments/assets/3a3c6bdb-620f-433e-8c43-00420a3c6e7d" />

---

### 3. Searched the `Investigation`
Step 3 - Investigation - With all the above alerts triggered we can definitely say that the virtual machine is compromised through the suspicious timeline. We can move forward in cleaning the machine from the virus. If we scroll down to event ID 8408, we can see a Powershell command that is initiating a “Invoke-WebRequest” command and downloaded AutoIt-v3-setup.exe from the following URI: 

https[:]//www.autoitscript.com/cgi-bin/getfile.pl?autoit3/autoit-v3-setup.exe

This is clearly the script downloading and installing the required AutoIt.exe program it needs to run the malicious script!And as a result we see that AutoIt.exe was ran and installed, which eventually lead to the execution of the calc.au3 malicious script (resulting in calculator being launched in our VM)

<img width="1336" height="809" alt="T1059_IOC_003" src="https://github.com/user-attachments/assets/8c1822ff-c45c-4aac-98ce-09930c7901bd" />

We also check stats of malicious activities in DeepblueCLI by running the following scripts as we can see we have thousands of brute force attacks starting from Nov 15th, using usernames to the likes of admin, ADMIN, ADMIN1, ADMINISTRATOR, and more. This shows enough based on the invoke web-request it was an opening for threat actors to attack our virtual machine through a calculator. Mainly because the firewalls on this machine is disabled. 



### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Step 4 - Containment and Eradication, Recovery - 

The containment strategey we are using is isolating the machine using Microsoft defender.  I gather all IP addresses, PCAP files, logs, hash values of suspected files (calc.au3.exe, etc.) and any indicators of compromise that will help build a legal case if needed.


## **Summary Report: T1059 – Command and Scripting Interpreter Incident**

On October 31st at 10:30 AM, a malicious actor successfully executed an atomic test script on the virtual machine **Threathunting‑LMP**, triggering multiple alerts in Microsoft Defender. Initial indicators of compromise included the unauthorized installation of **AutoIt.exe** via Internet Explorer and the repeated creation of **AutoIt3.exe** files. Log data confirmed that the initiating process was **autoit‑v3‑setup.exe**, executed under the account **latricemp711**.

Timeline analysis in Microsoft Defender revealed a key event at **10:28:17**, where **powershell.exe** remotely launched AutoIt3.exe with arguments pointing to a malicious script (**calc.au3**). This activity aligned with PE metadata and confirmed that the script was executed under the user context **Threathunting‑l\latricemp711**.

Further investigation uncovered a PowerShell **Invoke‑WebRequest** command (Event ID 8408) used to download AutoIt‑v3‑setup.exe from a public URI. This download enabled the installation of AutoIt, which subsequently executed the malicious calc.au3 script, demonstrated by the calculator application launching on the VM.

Additional threat‑hunting using DeepBlueCLI revealed **thousands of brute‑force attempts** beginning November 15th, targeting common administrative usernames such as *admin*, *ADMIN*, and *ADMINISTRATOR*. These attempts indicate that the disabled firewall and the malicious web‑request activity created an exploitable entry point for attackers.

### **Containment and Recovery**
The compromised VM was isolated using Microsoft Defender to prevent further lateral movement or external communication. All relevant evidence—including IP addresses, PCAP files, logs, and file hashes (e.g., calc.au3.exe)—was collected to support remediation efforts and potential legal action. The next steps involve full eradication of malicious components and restoration of the system to a secure state.

---



---
