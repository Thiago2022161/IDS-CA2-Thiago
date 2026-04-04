# Lightweight Network Intrusion Detection System (IDS)

CA2 capstone project for the **Problem Solving for Industry** module at **CCT College Dublin**.

## Authors

- **Sander Luiz Santos Soares** — 2022164
- **Thiago Gonçalves da Costa** — 2022161

## Academic Information

- **College:** CCT College Dublin
- **Programme:** BSc (Hons) in Computing in IT
- **Module:** Problem Solving for Industry
- **Assessment:** CA2 Project
- **Lecturers:** Muhammad Iqbal, Ken Healy

## Project Overview

This project proposes the development of a **Lightweight Network Intrusion Detection System (IDS)** using **Python** and **machine learning** techniques to detect suspicious or potentially malicious network traffic.

The system is designed to analyse **network flow data** and identify anomalies or attack patterns such as:

- DoS
- DDoS
- PortScan
- Brute Force
- Web Attacks
- Infiltration
- Botnet-related behaviour
- Other suspicious traffic patterns

The main goal is to build a **lightweight and affordable prototype** that can support organisations with limited cybersecurity resources, especially **small and medium-sized enterprises (SMEs)**, schools, clinics, small offices, and managed service providers.

## Main Objectives

- Detect malicious or suspicious network traffic
- Classify normal and attack traffic
- Explore the use of machine learning for lightweight intrusion detection
- Compare model performance using suitable evaluation metrics
- Generate alerts from suspicious flows
- Prepare a simple dashboard prototype for results visualisation

## Dataset

The main dataset used in this project is **CIC-IDS2017**, a public cybersecurity dataset developed by the **Canadian Institute for Cybersecurity**.

It contains labelled network traffic data with both **benign** and **malicious** behaviour, making it suitable for machine learning experimentation in intrusion detection.

The project may use multiple CSV files from the CIC-IDS2017 collection, depending on the scope of preprocessing, training, and evaluation.

## Technologies to be Used

- **Python**
- **Jupyter Notebook**
- **Pandas**
- **NumPy**
- **Scikit-learn**
- **Matplotlib / Seaborn**
- **Streamlit**
- **Pickle / Joblib**
