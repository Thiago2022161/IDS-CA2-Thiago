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
- **Framework:** CRISP-DM

## Project Overview

This project developed a **Lightweight Network Intrusion Detection System (IDS)** using **Python** and **machine learning** to classify benign and malicious network traffic.

The project follows the **CRISP-DM framework**, covering:

1. Business Understanding
2. Data Understanding
3. Data Preparation
4. Modelling
5. Evaluation
6. Deployment

The final solution uses a trained machine learning model and a simple **Streamlit dashboard prototype**, where a user can upload a CSV file containing network flow data and receive IDS predictions.

The system is designed as a lightweight and affordable prototype for organisations with limited cybersecurity resources, especially:

- Small and medium-sized enterprises (SMEs)
- Schools
- Clinics
- Small offices
- Managed Service Providers (MSPs)

## Main Objectives

- Analyse and preprocess the CICIDS2017 dataset
- Detect benign and malicious network traffic patterns
- Compare multiple machine learning models
- Address class imbalance and rare attack categories
- Evaluate models using accuracy, precision, recall, macro F1-score, weighted F1-score, runtime and confusion matrix analysis
- Select a lightweight and interpretable IDS model
- Build a simple Streamlit dashboard prototype for prediction and traffic summary visualisation

## Dataset

The dataset used in this project is **CICIDS2017**, a public cybersecurity dataset developed by the **Canadian Institute for Cybersecurity**.

The project used 8 CSV files from CICIDS2017 and merged them into one dataset.

The dataset includes benign traffic and several attack classes, including:

- BENIGN
- DoS Hulk
- DoS GoldenEye
- DoS slowloris
- DoS Slowhttptest
- DDoS
- PortScan
- Bot
- FTP-Patator
- SSH-Patator
- Web Attack Brute Force
- Web Attack XSS
- Web Attack Sql Injection
- Infiltration
- Heartbleed

After cleaning and preprocessing, the final full dataset kept **15 traffic classes**.

## Data Preparation Summary

The main data preparation steps included:

- Merging the 8 CICIDS2017 CSV files
- Removing leading/trailing spaces from column names
- Cleaning label formatting
- Handling infinite values
- Removing missing values
- Removing duplicate rows
- Removing constant features
- Encoding target labels using `LabelEncoder`
- Reducing highly correlated features
- Creating train/test splits using stratification
- Scaling features for Logistic Regression
- Preparing Full, Capped and Controlled dataset scenarios

The final reduced feature set contained **39 selected features**.

## Dataset Scenarios

Three dataset scenarios were used for modelling and evaluation.

### Full Dataset

The Full Dataset keeps all 15 traffic classes, including rare attacks.

This provides the widest attack coverage and was used for the final selected model.

### Capped Dataset

The Capped Dataset limits each class to a maximum of 10,000 records.

It keeps all 15 classes but is mainly used for faster experimentation and runtime comparison.

### Controlled Dataset

The Controlled Dataset removes classes with fewer than 1,000 records.

It improves metric stability but removes rare attack classes, reducing IDS attack coverage.

## Machine Learning Models

The following models were tested:

- Logistic Regression
- Random Forest
- Decision Tree

For each model, baseline and balanced versions were tested where appropriate.

- **Baseline** means the model was trained without `class_weight="balanced"`.
- **Balanced** means the model used `class_weight="balanced"` to give more importance to minority classes.

## Final Selected Model

The final selected model was:

```text
Decision Tree - Full Dataset Balanced Tuned 2
```

This model was selected because it provided the best overall balance between:

- Strong classification performance
- Runtime efficiency
- Interpretability
- Lightweight deployment suitability
- Attack coverage

Although the Controlled Dataset models achieved higher Macro F1-scores, they removed four rare attack classes:

- Heartbleed
- Infiltration
- Web Attack Sql Injection
- Web Attack XSS

For this reason, the final model was selected from the Full Dataset experiments because it preserved all 15 traffic classes.

## Final Model Performance

Final selected model:

```text
Decision Tree - Full Dataset Balanced Tuned 2
```

Main metrics:

```text
Accuracy: 0.998372
Macro Precision: 0.916101
Macro Recall: 0.903544
Macro F1-score: 0.909394
Weighted F1-score: 0.998367
Training Time: approximately 25 seconds
```

Rare-class results:

```text
Heartbleed: F1-score 1.00
Infiltration: F1-score 0.92
Web Attack Sql Injection: F1-score 0.75
Web Attack XSS: F1-score 0.42
```

## Streamlit Dashboard Prototype

A Streamlit dashboard was developed to demonstrate how the final model can be reused outside the notebook.

The dashboard allows the user to:

- Upload a CSV file containing network flow data
- Preview the uploaded data
- Check whether the required 39 features are present
- Remove invalid or incomplete rows
- Run IDS predictions using the saved model
- View benign and suspicious traffic counts
- View predicted traffic class distribution
- Review suspicious/attack traffic rows
- Download the prediction results as a CSV file
- View the most relevant traffic features used by the Decision Tree model

## Required Files for Dashboard

To run the dashboard, the following files must be kept in the same project folder:

```text
app.py
final_decision_tree_ids_model.pkl
label_encoder.pkl
model_features.pkl
```

The `.pkl` files are required because the dashboard loads the saved trained model and supporting objects.

File explanation:

```text
app.py – Streamlit dashboard application

final_decision_tree_ids_model.pkl – saved final Decision Tree IDS model

label_encoder.pkl – converts the model’s numerical predictions back into readable traffic class names

model_features.pkl – stores the 39 selected feature names required by the model
```

Without these `.pkl` files, the dashboard cannot run predictions.

A sample CSV file can also be included for testing, for example:

```text
dashboard_test_sample_with_label.csv
dashboard_test_sample_no_label.csv
```

## How to Run the Dashboard on Windows

1. Open the project folder in **Visual Studio Code**.

2. Open the terminal inside VS Code.

3. Navigate to the project folder if needed. Example:

```bash
cd C:\Users\YourName\Downloads\CA2-IDS
```

4. Run the Streamlit dashboard:

```bash
python -m streamlit run app.py
```

5. The dashboard should open automatically in the browser.

6. If it does not open automatically, open:

```text
http://localhost:8501
```

7. Upload a CSV file using the dashboard upload section.

8. Review the IDS predictions, class summaries, suspicious traffic table and downloadable output.

## How to Run the Dashboard on macOS

1. Open the project folder in **Visual Studio Code**.

2. Open the terminal inside VS Code.

3. Navigate to the project folder if needed. Example:

```bash
cd /Users/thiagogoncos/Downloads/CA2-IDS
```

4. If using Anaconda on macOS and a protobuf/libprotobuf error appears, run:

```bash
export PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python
```

5. Then run the dashboard:

```bash
python -m streamlit run app.py
```

6. The dashboard should open automatically in the browser.

7. If it does not open automatically, open:

```text
http://localhost:8501
```

## How to Use the Dashboard

1. Open the dashboard in the browser.

2. Click **Browse files** or drag and drop a CSV file into the upload area.

3. The uploaded CSV must contain network flow records with the same 39 selected features used during training.

4. The dashboard will preview the uploaded data.

5. The dashboard checks if the required features are present.

6. Invalid or incomplete rows are removed.

7. The saved Decision Tree model predicts the traffic class for each valid row.

8. The dashboard displays:

```text
Total analysed flows
Predicted benign traffic
Predicted suspicious/attack traffic
Prediction output table
Predicted class summary
Suspicious traffic summary
Most relevant traffic features
```

9. The final prediction results can be downloaded using the download button.

## Technologies Used

- Python
- Jupyter Notebook
- Pandas
- NumPy
- Scikit-learn
- Matplotlib
- Seaborn
- Streamlit
- Joblib

## Project Files

Recommended project structure:

```text
CA2-IDS/
│
├── app.py
├── IDS_CA2.ipynb
├── final_decision_tree_ids_model.pkl
├── label_encoder.pkl
├── model_features.pkl
├── dashboard_test_sample_with_label.csv
├── dashboard_test_sample_no_label.csv
│
├── Datasets/
│   └── CICIDS2017/
│
├── Report/
│   └── Sander2022164_Thiago2022161_Report.docx
│
├── Presentation/
│   └── Poster / presentation files
│
└── README.md
```

## Limitations

This dashboard is a prototype and not a full production IDS.

The current system does not capture live network packets directly. It only works with structured CSV network flow data using the same 39 selected features used during training.

For real-world use, an additional flow extraction layer would be needed to convert live network traffic or packet captures into the correct CSV format before prediction.

The model was trained on the CICIDS2017 dataset, which is a historical public dataset. Future work would require testing with newer network traffic data, retraining and further validation before real-world deployment.

## Final Conclusion

This project shows that a Decision Tree model can provide a strong and lightweight solution for multiclass network intrusion detection.

The final selected model preserved all 15 traffic classes, achieved strong overall performance, detected some rare attack classes and remained suitable for a simple dashboard prototype.

The Streamlit dashboard demonstrates how the trained model can be reused to support traffic classification, suspicious traffic summaries and downloadable IDS prediction results.