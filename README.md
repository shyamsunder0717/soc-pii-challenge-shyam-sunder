# ISCP 2.0 SOC-PII-Challenge – Real-Time PII Redactor

This repository houses my submission for the **Real-Time PII Defense** challenge as part of the **Flipkart ISCP 2.0 SOC-PII-Challenge** initiative. The goal? To equip systems with the ability to **detect and redact sensitive Personally Identifiable Information (PII)** from data streams—without slowing them down.

---

##  Challenge Overview

Flipkart recent security audit uncovered a key vulnerability: logs leaking personal data like names and addresses from external APIs. Fraudsters exploited these leaks to scam customers via OTP scams and unauthorized refunds.

**Your mission:** Develop a solution that can reliably:
1. Identify PII (both standalone and combinatorial).
2. Redact sensitive data in real time.
3. Maintain high accuracy and low latency.

That's exactly what this project delivers.

---

##  Features at a Glance

- Detects **Standalone PII**:
  - **Phone numbers** (exact 10-digit formats)
  - **Aadhar numbers** (12-digit numeric formats)
  - **Passport numbers** (alphanumeric, standard Indian format)
  - **UPI IDs** (user@bank-style strings)

- Detects **Combinatorial PII** (when two or more appear in the same record):
  - Full names (first + last)
  - Email addresses
  - Physical addresses (must include street, city, and pin)
  - Device IDs / IP addresses (when contextually tied)

- Smart redaction with pattern masking:
  - `9876543210` → `98XXXXXX10`
  - `1234 5678 9012` → `12XXXXXXXX12`
  - `rahul.kumar@upi` → `raXXX@upi`
  - `John Smith` → `JXXX SXXXX`

- Outputs a sanitized CSV with these columns:
  - `record_id`
  - `redacted_data_json`
  - `is_pii` (True/False flag)

---

##  Usage

### 1. Clone the repo
```bash
git clone https://github.com/shyamsunder0717/soc-pii-challenge-shyam-sunder.git
cd soc-pii-challenge-shyam-sunder
```

## 2. Run the detector
```
python detector_shyam_sunder.py iscp_pii_dataset_-_Sheet1.csv
```

### 3. Collect the results

A new file is generated:

`redacted_output_shyam_sunder.csv`

**Sample output:**

```csv
record_id,redacted_data_json,is_pii
1,"{""phone"": ""98XXXXXX10"", ""order_value"": 1299}",True
2,"{""name"": ""JXXX SXXXX"", ""email"": ""joXXX@gmail.com""}",True
```
## POTENTIAL DEPLOYMENT STRATEGY

For production use, this logic fits perfectly inside a Sidecar container deployed alongside services logging sensitive traffic. Here's why it works:

* **Low latency:** Redaction happens inline with the data flow.
* **Transparent integration:** No need to refactor existing services.
* **Scalable:** Scales easily with each service instance.

Alternatives could include:

* **API Gateway Plugin:** Sanitizes inbound/outbound traffic at the edge.
* **Kubernetes DaemonSet:** Hooks into node-level log ingestion.

## Deliverables

* `detector_shyam_sunder.py`: The PII detector & redactor.
* `redacted_output_shyam_sunder.csv`: Sample sanitized output.

## Technical Notes

* Written in Python, using only standard libraries (csv, json, re, sys).
* Built to minimize false positives, following precise definitions to meet high accuracy goals.
* Aims for an F1 score ≥ 0.95 on hidden test sets.

# Contact Information

* **Author:** Shyam Sunder
* **Registered CTF User Name:** shyamsunders0708
* **GitHub:** [soc-pii-challenge-shyam-sunder](https://github.com/shyamsunder0717/soc-pii-challenge-shyam-sunder)

