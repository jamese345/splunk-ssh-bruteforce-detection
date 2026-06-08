# SSH Brute Force Detection and Investigation using Splunk

## Project Overview

This project demonstrates the use of Splunk Enterprise for detecting, investigating, and visualizing SSH brute-force attacks using log analysis and threat hunting techniques.

The objective was to simulate the workflow of a Security Operations Center (SOC) analyst by ingesting SSH authentication logs, identifying suspicious behavior, building dashboards, and producing an incident investigation report.

## Scenario

An organization suspects malicious actors are attempting to gain unauthorized access to Linux servers through SSH.

As a SOC Analyst, I was tasked with:

- Monitoring SSH authentication activity
- Identifying failed login attempts
- Detecting brute-force behavior
- Investigating affected systems
- Producing security findings and recommendations

## Dataset

The dataset contains SSH authentication events in JSON format.

### Log Fields

| Field | Description |
|---------|-------------|
| id.orig_h | Source IP |
| id.resp_h | Destination IP |
| auth_attempts | Authentication Attempts |
| auth_success | Authentication Status |
| event_type | Event Classification |
| _time | Event Timestamp |

## Tools Used

- Splunk Enterprise 10.4
- SPL (Search Processing Language)
- JSON Log Data
- MITRE ATT&CK Framework
- GitHub

## Detection Queries

### Top Source IPs

``spl
index="ssh_logs" sourcetype="_json" auth_success="false"
| stats count by id.orig_h
| rename id.orig_h as source_ip
| sort - count

###Top Destination IPs
index="ssh_logs" sourcetype="_json"
| stats count by id.resp_h
| rename id.resp_h as destination_ip
| sort - count

### SSH Brute Force Detection
index="ssh_logs" auth_success="false"
| stats count by id.orig_h
| where count > 10
