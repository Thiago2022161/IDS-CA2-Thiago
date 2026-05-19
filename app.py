# Lightweight Network Intrusion Detection System - Streamlit App
# Prediction Workflow Version

# This version extends the initial dashboard by adding the full
# prediction workflow. The user can upload a CSV file, the app prepares
# the data, runs the saved IDS model, and displays prediction results.

# Import required libraries
# Streamlit is used to build the dashboard interface
import streamlit as st

# Pandas is used to read, clean and display CSV data
import pandas as pd

# NumPy is used to handle infinite values and create traffic status labels
import numpy as np

# Joblib is used to load the saved model and supporting objects
import joblib

# Page configuration
# Configure the Streamlit page title, icon and layout
st.set_page_config(
    page_title="Lightweight IDS Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Load saved model objects
@st.cache_resource
def load_saved_objects():
    """
    Load the saved IDS model and supporting files.
    """

    # Load trained model
    model = joblib.load("final_decision_tree_ids_model.pkl")

    # Load label encoder
    label_encoder = joblib.load("label_encoder.pkl")

    # Load list of expected model features
    feature_list = joblib.load("model_features.pkl")

    return model, label_encoder, feature_list


# Load saved model objects when the app starts
model, label_encoder, feature_list = load_saved_objects()

# Helper function: read CSV
def read_uploaded_csv(uploaded_file):
    """
    Read the uploaded CSV file.

    The app first tries the default encoding.
    If that fails, latin1 is used as a fallback.
    """

    try:
        # Try reading CSV normally
        data = pd.read_csv(uploaded_file)

    except UnicodeDecodeError:
        # Reset file pointer before reading again
        uploaded_file.seek(0)

        # Read CSV using latin1 encoding
        data = pd.read_csv(uploaded_file, encoding="latin1")

    return data

# Helper function: prepare input data
def prepare_input_data(data, feature_list):
    """
    Prepare uploaded network flow data before prediction.

    This function:
    - removes extra spaces from column names;
    - checks if required columns are present;
    - keeps only the columns used by the model;
    - converts values to numeric;
    - replaces infinite values with missing values;
    - removes invalid rows.
    """

    # Remove leading and trailing spaces from column names
    data.columns = data.columns.str.strip()

    # Check if any required model feature is missing
    missing_features = [
        feature for feature in feature_list
        if feature not in data.columns
    ]

    # If required features are missing, stop preparation
    if len(missing_features) > 0:
        return None, missing_features, None

    # Keep only required features in the correct order
    X_input = data[feature_list].copy()

    # Convert all values to numeric
    for col in X_input.columns:
        X_input[col] = pd.to_numeric(X_input[col], errors="coerce")

    # Replace infinite values with NaN
    X_input = X_input.replace([np.inf, -np.inf], np.nan)

    # Count rows before removing invalid records
    rows_before = X_input.shape[0]

    # Remove rows with missing or invalid values
    X_input_clean = X_input.dropna()

    # Count removed rows
    rows_removed = rows_before - X_input_clean.shape[0]

    return X_input_clean, missing_features, rows_removed

# Helper function: predict traffic
def predict_network_traffic(input_data, model, label_encoder):
    """
    Predict traffic classes for uploaded network flow records.
    """

    # Generate numeric predictions
    predictions_encoded = model.predict(input_data)

    # Convert numeric predictions into readable class names
    predictions_labels = label_encoder.inverse_transform(predictions_encoded)

    return predictions_labels

# Helper function: prediction summary
def create_prediction_summary(prediction_df):
    """
    Create a summary table with the number of flows per predicted class.
    """

    # Count each predicted label
    summary = (
        prediction_df["Predicted Label"]
        .value_counts()
        .reset_index()
    )

    # Rename columns
    summary.columns = ["Predicted Label", "Count"]

    return summary

# Dashboard title and introduction
# Main dashboard title
st.title("🛡️ Lightweight Network Intrusion Detection System")

# Dashboard subtitle
st.subheader("Network Traffic Analysis Dashboard")

# User-facing dashboard description
st.markdown(
    """
    Upload a network flow CSV file to analyse traffic activity and identify possible suspicious or attack-related flows.

    The dashboard classifies each flow, summarises the results, highlights suspicious traffic, and allows the prediction output to be downloaded.
    """
)

# Sidebar instructions
# Sidebar title
st.sidebar.title("How to use")

# Usage instructions
st.sidebar.markdown(
    """
    1. Upload a network flow CSV file.
    2. Review the uploaded data preview.
    3. Check the automatic traffic classification.
    4. Review benign and suspicious traffic summaries.
    5. Download the prediction results if needed.
    """
)

# Separator line
st.sidebar.markdown("---")

# Traffic status explanation
st.sidebar.markdown(
    """
    **Traffic status:**

    **Benign** = normal traffic  
    **Suspicious / Attack** = traffic classified as an attack category
    """
)

# File upload section
# Section title
st.markdown("## Upload Network Flow CSV")

# File uploader widget
uploaded_file = st.file_uploader(
    "Upload a CSV file containing network flow records",
    type=["csv"]
)

# Main prediction workflow
# Only run after a file is uploaded
if uploaded_file is not None:

    # Read uploaded CSV
    df_uploaded = read_uploaded_csv(uploaded_file)

    # Confirm successful upload
    st.success("CSV file uploaded successfully.")

    # Show uploaded data preview
    st.markdown("### Uploaded Data Preview")
    st.dataframe(df_uploaded.head())

    # Show uploaded data shape
    st.markdown("### Uploaded Data Shape")

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Rows", df_uploaded.shape[0])

    with col2:
        st.metric("Columns", df_uploaded.shape[1])

    # Prepare uploaded data for prediction
    X_input_clean, missing_features, rows_removed = prepare_input_data(
        df_uploaded,
        feature_list
    )

    # Stop if required columns are missing
    if X_input_clean is None:
        st.error("The uploaded file is missing required network flow columns.")

        st.markdown("### Missing Columns")
        st.write(missing_features)

        st.warning(
            "Please upload a CSV file with the correct network flow structure."
        )

        st.stop()

    # Show input preparation summary
    st.markdown("### Input Preparation Summary")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Original Rows", df_uploaded.shape[0])

    with col2:
        st.metric("Rows Analysed", X_input_clean.shape[0])

    with col3:
        st.metric("Rows Removed", rows_removed)

    # Warn if rows were removed
    if rows_removed > 0:
        st.warning(
            "Some rows were removed because they contained missing or invalid values."
        )

    # Run model prediction
    predictions = predict_network_traffic(
        X_input_clean,
        model,
        label_encoder
    )

    # Create prediction results dataframe
    prediction_results = X_input_clean.copy()
    prediction_results["Predicted Label"] = predictions

    # If uploaded CSV contains Label column, use it only for comparison
    if "Label" in df_uploaded.columns:
        original_labels = df_uploaded.loc[X_input_clean.index, "Label"].astype(str).str.strip()

        prediction_results["Actual Label"] = original_labels

        prediction_results["Correct Prediction"] = (
            prediction_results["Actual Label"] == prediction_results["Predicted Label"]
        )

    # Create simpler traffic status
    prediction_results["Traffic Status"] = np.where(
        prediction_results["Predicted Label"] == "BENIGN",
        "Benign",
        "Suspicious / Attack"
    )

    # Results overview
    st.markdown("## Prediction Results")

    # Calculate summary counts
    total_flows = prediction_results.shape[0]
    benign_count = (prediction_results["Predicted Label"] == "BENIGN").sum()
    suspicious_count = total_flows - benign_count

    # Display high-level metrics
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Total Analysed Flows", total_flows)

    with col2:
        st.metric("Predicted Benign", benign_count)

    with col3:
        st.metric("Predicted Suspicious / Attack", suspicious_count)

    # Prediction output table
    st.markdown("### Prediction Output Table")

    # Default display columns
    display_columns = ["Predicted Label", "Traffic Status"]

    # Include actual labels if available
    if "Actual Label" in prediction_results.columns:
        display_columns = [
            "Actual Label",
            "Predicted Label",
            "Correct Prediction",
            "Traffic Status"
        ]

    # Display first 100 prediction rows
    st.dataframe(prediction_results[display_columns].head(100))

    st.info(
        "The table shows the first 100 prediction results. "
        "The full output can be downloaded below."
    )

    # Predicted class summary
    st.markdown("### Predicted Class Summary")

    # Create and display summary table
    prediction_summary = create_prediction_summary(prediction_results)
    st.dataframe(prediction_summary)

    # Predicted class distribution
    st.markdown("### Predicted Traffic Class Distribution")

    # Display bar chart
    st.bar_chart(
        prediction_summary.set_index("Predicted Label")
    )

    # Suspicious traffic summary
    st.markdown("### Suspicious Traffic Summary")

    # Filter suspicious/attack flows
    suspicious_flows = prediction_results[
        prediction_results["Predicted Label"] != "BENIGN"
    ]

    # Show suspicious flow table if any attack is detected
    if suspicious_flows.shape[0] > 0:
        st.warning(f"{suspicious_flows.shape[0]} suspicious or attack flows were detected.")

        st.dataframe(
            suspicious_flows[display_columns].head(100)
        )

    else:
        st.success("No suspicious or attack traffic was detected in this uploaded file.")

    # Download prediction results
    st.markdown("### Download Prediction Results")

    # Convert full prediction results to CSV
    csv_output = prediction_results.to_csv(index=False).encode("utf-8")

    # Create download button
    st.download_button(
        label="Download prediction results as CSV",
        data=csv_output,
        file_name="ids_prediction_results.csv",
        mime="text/csv"
    )

else:
    # Default message before upload
    st.info("Please upload a CSV file to start the traffic analysis.")