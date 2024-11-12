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
