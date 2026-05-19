# Lightweight Network Intrusion Detection System - Streamlit App
# Initial Dashboard Version

# This first version creates the basic Streamlit dashboard structure.
# It loads the saved IDS model objects and allows the user to upload
# a CSV file for preview.

# Import required libraries

# Streamlit is used to build the dashboard interface
import streamlit as st

# Pandas is used to read and display uploaded CSV files
import pandas as pd

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

    These objects were generated in the notebook after training
    the final selected model.
    """

    # Load trained model
    model = joblib.load("final_decision_tree_ids_model.pkl")

    # Load label encoder
    label_encoder = joblib.load("label_encoder.pkl")

    # Load list of features expected by the model
    feature_list = joblib.load("model_features.pkl")

    return model, label_encoder, feature_list

# Load saved objects when the app starts
model, label_encoder, feature_list = load_saved_objects()

# Dashboard title and introduction
# Main dashboard title
st.title("🛡️ Lightweight Network Intrusion Detection System")

# Dashboard subtitle
st.subheader("Network Traffic Analysis Dashboard")

# User-facing description
st.markdown(
    """
    Upload a network flow CSV file to analyse traffic activity and identify possible suspicious or attack-related flows.
    """
)

# Sidebar instructions
# Sidebar title
st.sidebar.title("How to use")

# Basic usage instructions
st.sidebar.markdown(
    """
    1. Upload a network flow CSV file.
    2. Review the uploaded data preview.
    3. Continue with traffic analysis.
    """
)

# Helper function: read CSV
def read_uploaded_csv(uploaded_file):
    """
    Read the uploaded CSV file.

    If the default encoding fails, latin1 is used as a fallback.
    """

    try:
        # Try reading the file normally
        data = pd.read_csv(uploaded_file)

    except UnicodeDecodeError:
        # Reset file pointer before trying again
        uploaded_file.seek(0)

        # Try latin1 encoding
        data = pd.read_csv(uploaded_file, encoding="latin1")

    return data

# File upload section
# Section title
st.markdown("## Upload Network Flow CSV")

# File upload widget
uploaded_file = st.file_uploader(
    "Upload a CSV file containing network flow records",
    type=["csv"]
)

# Uploaded file preview
# Only run this section after a file is uploaded
if uploaded_file is not None:

    # Read uploaded CSV
    df_uploaded = read_uploaded_csv(uploaded_file)

    # Confirm upload
    st.success("CSV file uploaded successfully.")

    # Show preview of uploaded data
    st.markdown("### Uploaded Data Preview")
    st.dataframe(df_uploaded.head())

    # Show shape of uploaded data
    st.markdown("### Uploaded Data Shape")

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Rows", df_uploaded.shape[0])

    with col2:
        st.metric("Columns", df_uploaded.shape[1])

else:
    # Default message before upload
    st.info("Please upload a CSV file to start the traffic analysis.")