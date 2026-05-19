# Lightweight Network Intrusion Detection System - Streamlit App

# This Streamlit dashboard allows the user to upload a CSV file
# containing network flow data and receive traffic classification results.
# The app loads the final trained IDS model and uses it to classify each
# uploaded network flow as BENIGN or as a specific attack category.

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
    Load the trained IDS model and supporting files.

    These files were created from the notebook after the final model was trained.
    They are required so the dashboard can make predictions without retraining the model.
    """

    # Load the final trained IDS model
    model = joblib.load("final_decision_tree_ids_model.pkl")

    # Load the label encoder to convert numeric predictions into readable class names
    label_encoder = joblib.load("label_encoder.pkl")

    # Load the list of columns expected by the model
    feature_list = joblib.load("model_features.pkl")

    return model, label_encoder, feature_list

# Load model, label encoder and feature list when the app starts
model, label_encoder, feature_list = load_saved_objects()

# Helper function: read CSV
def read_uploaded_csv(uploaded_file):
    """
    Read the uploaded CSV file.

    The app first tries to read the file using the default encoding.
    If that fails, it tries latin1 encoding as a fallback.
    """

    try:
        # Try reading the CSV normally
        data = pd.read_csv(uploaded_file)

    except UnicodeDecodeError:
        # Reset file pointer before trying again
        uploaded_file.seek(0)

        # Read CSV using latin1 encoding if default encoding fails
        data = pd.read_csv(uploaded_file, encoding="latin1")

    return data

# Helper function: prepare input data
def prepare_input_data(data, feature_list):
    """
    Prepare the uploaded network flow data before prediction.

    This function:
    - removes extra spaces from column names;
    - checks if all required columns are available;
    - keeps only the columns required by the model;
    - converts values to numeric format;
    - replaces infinite values with missing values;
    - removes rows with invalid or missing values.
    """

    # Remove leading and trailing spaces from column names
    data.columns = data.columns.str.strip()

    # Check which required columns are missing from the uploaded file
    missing_features = [
        feature for feature in feature_list
        if feature not in data.columns
    ]

    # If any required column is missing, return None and stop preparation
    if len(missing_features) > 0:
        return None, missing_features, None

    # Keep only the columns required by the model and preserve the correct order
    X_input = data[feature_list].copy()

    # Convert all selected columns to numeric values
    # Any value that cannot be converted becomes NaN
    for col in X_input.columns:
        X_input[col] = pd.to_numeric(X_input[col], errors="coerce")

    # Replace positive and negative infinite values with NaN
    X_input = X_input.replace([np.inf, -np.inf], np.nan)

    # Count rows before removing invalid records
    rows_before = X_input.shape[0]

    # Remove rows with missing or invalid values
    X_input_clean = X_input.dropna()

    # Count how many rows were removed
    rows_removed = rows_before - X_input_clean.shape[0]

    return X_input_clean, missing_features, rows_removed

# Helper function: predict traffic
def predict_network_traffic(input_data, model, label_encoder):
    """
    Predict traffic classes for the uploaded network flow records.
    """
    # Generate numeric predictions from the model
    predictions_encoded = model.predict(input_data)

    # Convert numeric predictions back to readable class names
    predictions_labels = label_encoder.inverse_transform(predictions_encoded)

    return predictions_labels

# Helper function: prediction summary
def create_prediction_summary(prediction_df):
    """
    Create a summary table showing how many flows were predicted
    for each traffic class.
    """
    # Count predicted labels
    summary = (
        prediction_df["Predicted Label"]
        .value_counts()
        .reset_index()
    )

    # Rename columns for better display
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

# Simple usage instructions for the user
st.sidebar.markdown(
    """
    1. Upload a network flow CSV file.
    2. Review the uploaded data preview.
    3. Check the automatic traffic classification.
    4. Review benign and suspicious traffic summaries.
    5. Download the prediction results if needed.
    """
)

# Separator line in the sidebar
st.sidebar.markdown("---")

# Explain traffic status labels in simple terms
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
# Only run the prediction workflow after a file is uploaded
if uploaded_file is not None:

    # Read uploaded CSV
    # Read CSV file into a dataframe
    df_uploaded = read_uploaded_csv(uploaded_file)

    # Confirm successful upload
    st.success("CSV file uploaded successfully.")

    # Uploaded data preview
    # Show the first rows of the uploaded file
    st.markdown("### Uploaded Data Preview")
    st.dataframe(df_uploaded.head())

    # Show uploaded dataset shape
    st.markdown("### Uploaded Data Shape")

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Rows", df_uploaded.shape[0])

    with col2:
        st.metric("Columns", df_uploaded.shape[1])

    # Prepare data for prediction
    # Clean and prepare uploaded data for the model
    X_input_clean, missing_features, rows_removed = prepare_input_data(
        df_uploaded,
        feature_list
    )

    # If required columns are missing, show error and stop app execution
    if X_input_clean is None:
        st.error("The uploaded file is missing required network flow columns.")

        st.markdown("### Missing Columns")
        st.write(missing_features)

        st.warning(
            "Please upload a CSV file with the correct network flow structure."
        )

        st.stop()

    # Input preparation summary
    # Show how many rows were kept or removed before prediction
    st.markdown("### Input Preparation Summary")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Original Rows", df_uploaded.shape[0])

    with col2:
        st.metric("Rows Analysed", X_input_clean.shape[0])

    with col3:
        st.metric("Rows Removed", rows_removed)

    # Show warning if any rows were removed
    if rows_removed > 0:
        st.warning(
            "Some rows were removed because they contained missing or invalid values."
        )

    # Run prediction
    # Use the trained model to predict traffic labels
    predictions = predict_network_traffic(
        X_input_clean,
        model,
        label_encoder
    )

    # Create dataframe with the cleaned input data and predictions
    prediction_results = X_input_clean.copy()
    prediction_results["Predicted Label"] = predictions

    # Optional actual label comparison
    # If the uploaded CSV contains the real Label column,
    # use it only to compare actual vs predicted results.
    # The model does not use this Label column for prediction.
    if "Label" in df_uploaded.columns:
        original_labels = df_uploaded.loc[X_input_clean.index, "Label"].astype(str).str.strip()

        prediction_results["Actual Label"] = original_labels

        prediction_results["Correct Prediction"] = (
            prediction_results["Actual Label"] == prediction_results["Predicted Label"]
        )

    # Create traffic status column
    # Convert predicted labels into a simpler status:
    # BENIGN = normal traffic
    # anything else = suspicious or attack traffic
    prediction_results["Traffic Status"] = np.where(
        prediction_results["Predicted Label"] == "BENIGN",
        "Benign",
        "Suspicious / Attack"
    )

    # Results overview
    # Section title
    st.markdown("## Prediction Results")

    # Calculate summary counts
    total_flows = prediction_results.shape[0]
    benign_count = (prediction_results["Predicted Label"] == "BENIGN").sum()
    suspicious_count = total_flows - benign_count

    # Display high-level prediction metrics
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Total Analysed Flows", total_flows)

    with col2:
        st.metric("Predicted Benign", benign_count)

    with col3:
        st.metric("Predicted Suspicious / Attack", suspicious_count)

    # Prediction output table
    # Section title
    st.markdown("### Prediction Output Table")

    # Default columns if actual labels are not available
    display_columns = ["Predicted Label", "Traffic Status"]

    # If actual labels are available, include comparison columns
    if "Actual Label" in prediction_results.columns:
        display_columns = [
            "Actual Label",
            "Predicted Label",
            "Correct Prediction",
            "Traffic Status"
        ]

    # Display first 100 prediction results
    st.dataframe(prediction_results[display_columns].head(100))

    # Inform user that only the first 100 rows are displayed
    st.info(
        "The table shows the first 100 prediction results. "
        "The full output can be downloaded below."
    )

    # Predicted class summary
    # Section title
    st.markdown("### Predicted Class Summary")

    # Create summary table with count per predicted class
    prediction_summary = create_prediction_summary(prediction_results)

    # Display summary table
    st.dataframe(prediction_summary)

    # Predicted traffic class distribution
    # Section title
    st.markdown("### Predicted Traffic Class Distribution")

    # Display a simple Streamlit bar chart of predicted class counts
    st.bar_chart(
        prediction_summary.set_index("Predicted Label")
    )

    # Suspicious traffic summary
    # Section title
    st.markdown("### Suspicious Traffic Summary")

    # Filter only flows predicted as attack/suspicious
    suspicious_flows = prediction_results[
        prediction_results["Predicted Label"] != "BENIGN"
    ]

    # If suspicious traffic exists, show warning and table
    if suspicious_flows.shape[0] > 0:
        st.warning(f"{suspicious_flows.shape[0]} suspicious or attack flows were detected.")

        st.dataframe(
            suspicious_flows[display_columns].head(100)
        )

    # If no suspicious traffic exists, show success message
    else:
        st.success("No suspicious or attack traffic was detected in this uploaded file.")

    # Download prediction results
    # Section title
    st.markdown("### Download Prediction Results")

    # Convert prediction results dataframe to CSV bytes
    csv_output = prediction_results.to_csv(index=False).encode("utf-8")

    # Create download button for full prediction output
    st.download_button(
        label="Download prediction results as CSV",
        data=csv_output,
        file_name="ids_prediction_results.csv",
        mime="text/csv"
    )

# Default screen before upload
else:
    # Message shown before a file is uploaded
    st.info("Please upload a CSV file to start the traffic analysis.")

# Feature importance section
# Separator line
st.markdown("---")

# Section title
st.markdown("## Most Relevant Traffic Features")

# Short user-friendly explanation
st.markdown(
    """
    The table below shows the traffic features that had the highest influence on the classification process.
    """
)

# Check if the model provides feature importance values
if hasattr(model, "feature_importances_"):

    # Create feature importance dataframe
    feature_importance = pd.DataFrame({
        "Feature": feature_list,
        "Importance": model.feature_importances_
    })

    # Sort features by importance
    feature_importance = feature_importance.sort_values(
        by="Importance",
        ascending=False
    ).reset_index(drop=True)

    # Display the top 15 most relevant features
    st.markdown("### Top 15 Features")
    st.dataframe(feature_importance.head(15))

else:
    # Message shown if model does not provide feature importance
    st.warning("Feature importance is not available for this model.")