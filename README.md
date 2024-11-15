# Automated Incident Detection and Response

## Project Overview
In this lab, we will build an automated incident response workflow by integrating an **EDR (Endpoint Detection and Response)** solution, LimaCharlie, with a **SOAR (Security Orchestration, Automation, and Response)** platform, Tines. This setup will monitor for potential threats, automatically notify SOC (Security Operations Center) analysts through multiple channels, including Slack (for real-time alerts) and SquareX (for detailed email notifications), and allow users to trigger response actions, such as isolating compromised devices, in a simulated environment.

## Objectives
- Simulate a security monitoring environment and practice incident response techniques.
- Create detection and response rules within LimaCharlie.
- Build an automated workflow using Tines SOAR for faster response actions.
- Set up Slack alerts and use SquareX for email notifications containing detailed attack reports.
- Develop a SOC analyst response that can isolate compromised devices automatically.

## Prerequisites
To complete this lab, ensure you have:
- **Access to a Windows VM** (Virtual Machine) either in the cloud or on your local machine (using Hyper-V, VMware, or VirtualBox).
- Accounts on these platforms: **Tines**, **LimaCharlie**, **Slack**, and **SquareX**.

## Tools Overview

### SOAR (Security Orchestration, Automation, and Response)
We’ll use **Tines**, an open-source SOAR tool. Tines enables SOC teams to automate repetitive tasks, orchestrate complex workflows, and streamline incident response processes, reducing the time needed to mitigate security threats.

### EDR (Endpoint Detection and Response)
Our EDR tool for this lab is **LimaCharlie**, which continuously monitors and collects data from endpoints (e.g., computers, servers, mobile devices) to detect suspicious activities and take appropriate actions before potential breaches escalate.

### Windows VM
A **Windows Virtual Machine** will serve as our controlled test environment for simulated attacks.

### Slack
Slack will be used as a messaging platform for real-time alerts and notifications to the SOC team.

### SquareX
SquareX, a disposable email service, will be used for sending detailed email notifications to the SOC team regarding detected threats.

## Setting Up LimaCharlie on a Windows VM

### Step 1: Deploy a Windows VM
Start by deploying a **Windows VM**. You can set it up:
- On-premises on your host computer using **Hyper-V**, **VMware**, or **VirtualBox**.
- In the cloud using providers like **Azure**, **AWS**, **Vultr**, **GCP**, or **DigitalOcean**.

### Step 2: Sign Up with LimaCharlie
1. Go to the [LimaCharlie website](https://www.limacharlie.io/) and sign up for a free account.
2. Once your account is created, log in to the LimaCharlie portal.

### Step 3: Generate Installation Key in LimaCharlie
1. In the LimaCharlie portal, navigate to the **Sensors** tab.
2. Select **Installation Keys** and click on **Create Installation Key**.
3. For the description, enter a name like “SOAR-EDR-Project” to identify this key.
4. Once created, the new key will appear under **Installation Keys**.

This **Installation Key** will be required to install the LimaCharlie agent on your Windows VM.

### Step 4: Install the LimaCharlie Agent on the Windows VM
1. Connect to your Windows VM.
2. Download the **LimaCharlie Windows Agent** (64-bit) using the [download link](https://downloads.limacharlie.io/sensor/windows/64) provided in the **Installation Keys** tab in the LimaCharlie portal.
3. Copy the **Sensor Key** created in Step 3, as we’ll need it to complete the installation.

### Installing the Agent
1. Open an admin PowerShell terminal in the directory where the agent file is downloaded.
2. Run the following command to install the agent, replacing `lc_sensor.exe` with the downloaded file name and `YOUR_INSTALLATION_KEY` with your actual Sensor Key:
   ```powershell
   .\lc_sensor.exe -i YOUR_INSTALLATION_KEY
   ```

3. After installation, go to **Services** in the Windows VM, and you should see that the **LimaCharlie agent** is running.

### Step 5: Verify the Sensor in LimaCharlie
1. Go back to the LimaCharlie portal, and under the **Sensors** tab, navigate to the **Sensors List**.
2. You should see your Windows VM listed here. Click on it to view additional details.

### Exploring the Endpoint
- **File System**: View, download, and check file hashes (useful for identifying malware via VirusTotal).
- **Autorun**: Check for persistent startup items that may indicate malware.
- **Drivers**: Review drivers installed on the VM to detect any suspicious activity.
- **Console**: Send commands directly to the endpoint.
- **Network**: Monitor network processes and detect connections to any malicious IPs.
- **Timeline**: Track events in chronological order for incident analysis.

## Install Credential Dump Tool LaZagne

### Step 1: Preparing the Windows Server VM
1. **Disable Windows Defender:** First, disable Windows Defender on your Windows Server VM. This will allow us to download and run LaZagne without it being blocked.
2. **Download LaZagne:** Go to the official GitHub repository for LaZagne: [GitHub - AlessandroZ/LaZagne](https://github.com/AlessandroZ/LaZagne). You might see a warning about the download’s safety—ignore this by clicking on the three dots and selecting **Keep Anyway**.

### Step 2: Running LaZagne and Checking Telemetry in LimaCharlie
1. **Run LaZagne:** Execute the LaZagne tool in a admin PowerShell terminal on your VM to initiate the credential-stealing simulation.
2. **Check telemetry in LimaCharlie:** Go to LimaCharlie, go to the **Timeline** tab, and search for “LaZagne.” In the first `New_Process` event, we’ll see details like:
   - **Parent Process** (e.g., PowerShell)
   - **File Path**
   - **Process ID and Parent Process ID**
   - **Command Line**
   - **Hash**
   - **User Name**

### Step 3: Create a Detection & Response (D&R) Rule in LimaCharlie

Now, we’ll create a custom rule in LimaCharlie to detect LaZagne’s activity.

1. **Navigate to Automation**:
   - Open a new tab and go to the **Automation** tab in LimaCharlie.

2. **Create a Custom Rule**:
   - Under **D&R Rules**, click on **Create Custom Rule**.

3. **Use an Existing Template**:
   - To simplify rule creation, find an existing rule that detects process creation and copy it as a template.

Here is an example of a D&R rule to detect LaZagne:

```yaml
detect:
  events:
    - NEW_PROCESS
    - EXISTING_PROCESS
  op: and
  rules:
    - op: is windows
    - op: or
      rules:
        - case sensitive: false
          op: ends with
          path: event/FILE_PATH
          value: LaZagne.exe
        - case sensitive: false
          op: contains
          path: event/COMMAND_LINE
          value: LaZagne
        - case sensitive: false
          op: is
          path: event/HASH
          value: '3cc5ee93a9ba1fc57389705283b760c8bd61f35e9398bbfa3210e2becf6d4b05'
respond:
  - action: report
    metadata:
      author: SocLab
      description: Detects LaZagne Usage
      falsepositives:
        - None expected
      level: high
      tags:
        - attack.credential_access
    name: SocLab - HackingTool - LaZagne
```

### Rule Breakdown:
- **Event Types**: Triggers on **NEW_PROCESS** or **EXISTING_PROCESS**.
- **Operating System**: Targets **Windows** systems.
- **Detection Parameters**:
  - Checks if the **FILE_PATH** ends with `LaZagne.exe`.
  - Looks for "LaZagne" in the **COMMAND_LINE**.
  - Matches the **HASH** of the LaZagne executable.

### Implementing the Custom Detection Rule:
1. Copy this modified rule into your new custom rule in LimaCharlie.
2. Paste an example event of LaZagne to test if your rule correctly detects LaZagne.

### Step 4: Clear Detections and Run LaZagne Again
1. **Delete Existing Detections:** For a clean slate, delete previous detections in the **Detections** tab.
2. **Re-run LaZagne with `/all` Argument:** On your Windows Server VM, run `lazagne.exe /all` and check LimaCharlie’s **Detections** tab again to confirm your rule has detected it.

### Bonus Step: Detecting Mimikatz
1. **Download Mimikatz:** Get Mimikatz from [GitHub - gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz), extract the file, and open PowerShell as admin.
2. **Run Commands:**
   ```powershell
   privilege::debug
   sekurlsa::logonpasswords
   ```
3. **Check LimaCharlie Detections:** Mimikatz should trigger the built-in detection rules in LimaCharlie designed for Mimikatz.

## Signing Up for Slack, SquareX, and Tines

### Slack Setup

1. **Sign Up on Slack**:
   - Visit [Slack](https://slack.com) and choose the free version to sign up.
2. **Create a Channel**:
   - Once your account is set up, create a new channel named `#alert`.
   - This channel will receive the detection alerts from Tines.

### SquareX Setup

1. **Sign Up for SquareX**:
   - Visit [SquareX](https://sqrx.com) and sign up to receive emails from Tines.

### Tines Setup

1. **Sign Up on Tines**:
   - Go to [Tines](https://tines.com) and sign up.
2. **Explore the Interface**:
   - Upon signing in, you can drag and drop the necessary apps from the left into the middle of your "story" or "playbook".
3. **Clear Default Apps**:
   - Delete the two default apps in the middle to start fresh.
