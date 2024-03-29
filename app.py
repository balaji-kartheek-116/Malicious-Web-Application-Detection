import streamlit as st
import re
import numpy as np
from urllib.parse import urlparse
from tld import get_tld
import joblib
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# Function to check if URL uses HTTPS
def httpSecure(url):
    scheme = urlparse(url).scheme
    if scheme == 'https':
        return 1
    else:
        return 0

# Function to extract features from URL
def extract_features(url):
    # Length of the URL
    url_len = len(url)
    
    # Domain extraction
    domain = process_tld(url)
    
    # Count occurrences of special characters in the URL
    special_chars = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//']
    special_char_counts = [url.count(char) for char in special_chars]
    
    # Check for abnormal URL
    abnormal_url_flag = abnormal_url(url)
    
    # Check if URL uses HTTPS
    https_flag = http_secure(url)
    
    # Count the number of digits and letters in the URL
    digit_count = sum(c.isdigit() for c in url)
    letter_count = sum(c.isalpha() for c in url)
    
    # Check for URL shortening service
    shortening_service_flag = shortening_service(url)
    
    # Check for presence of an IP address in the URL
    ip_address_flag = having_ip_address(url)
    
    # Return extracted features as a list
    return [url_len] + special_char_counts + [abnormal_url_flag] + [https_flag] + [digit_count] + [letter_count] + [shortening_service_flag] + [ip_address_flag]

# Function to process top-level domain (TLD)
def process_tld(url):
    try:
        res = get_tld(url, as_object=True, fail_silently=False, fix_protocol=True)
        pri_domain = res.parsed_url.netloc
    except:
        pri_domain = None
    return pri_domain

# Function to check if URL uses HTTPS
def http_secure(url):
    scheme = urlparse(url).scheme
    if scheme == 'https':
        return 1
    else:
        return 0

# Function to check for abnormal URL
def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        return 1
    else:
        return 0

# Function to check for URL shortening service
def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0

# Function to check for presence of an IP address in the URL
def having_ip_address(url):
    match = re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                      '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
                      '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                      '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4 with port
                      '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
                      '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
                      '([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
                      '((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)', url)  # Ipv6
    if match:
        return 1
    else:
        return 0

# Load the saved Random Forest model
loaded_rf_model = joblib.load('decision_tree_model.pkl')

# Function to test a URL using the Random Forest model
def test_url_with_random_forest(url):
    # Extract features for the input URL
    features = extract_features(url)
    
    # Reshape the features to match the input shape of the model
    features = np.array(features).reshape(1, -1)
    
    # Predict using the Random Forest model
    prediction = loaded_rf_model.predict(features)
    
    # Return prediction
    return 'Anonymous' if prediction == 1 else 'Legitimate'

# Streamlit UI
def main():
    st.title("Malicious Web Application Detection")
    st.image("image.png")
    st.write("This app predicts whether a given URL is legitimate or potentially harmful.")
    
    # Sidebar for login/logout
    st.sidebar.title("Login")
    
    # Initialize session_state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")
    login_button = st.sidebar.button("Login")
    
    # Check credentials
    if login_button:
        if username == "admin" and password == "password":
            st.session_state.authenticated = True

    # Show main content if authenticated
    if st.session_state.authenticated:
        # User input URL
        user_input_url = st.text_input("Enter a URL to test:")
        
        # Perform prediction when button is clicked
        if st.button("Check URL"):
            if user_input_url:
                prediction = test_url_with_random_forest(user_input_url)
                st.write("Prediction result for the input URL:", prediction)
            else:
                st.write("Please enter a URL to test.")
        
        # Sample dataframe
        st.subheader("Sample DataFrame")
        data = pd.read_csv('new_dataset.csv')

        # Assuming 'data' is your DataFrame
        data['type'] = data['type'].replace({'benign': 'legitimate', 'phishing': 'anonymous', 'defacement': 'anonymous', 'malware': 'anonymous'})

        st.write(data.head())
        
        # Visualizations
        st.subheader("Visualizations")
        count = data.type.value_counts()
        
        # Visualization 1: Bar plot of URL types
        st.write("1. Bar plot of URL types")
        fig, ax = plt.subplots()
        sns.barplot(x=count.index, y=count, ax=ax)
        ax.set_xlabel('Types')
        ax.set_ylabel('Count')
        st.pyplot(fig)

        data['abnormal_url'] = data['url'].apply(lambda i: abnormal_url(i))
        # Visualization 2: Count plot of abnormal URLs
        st.write("2. Count plot of abnormal URLs")
        sns.countplot(x='abnormal_url', data=data);
        plt.xlabel('URL Types')
        plt.ylabel('Count');
        st.pyplot()

        data['https'] = data['url'].apply(lambda i: httpSecure(i))
        # Visualization 3: Count plot of HTTPS
        st.write("3. Count plot of HTTPS")
        sns.countplot(x='https', data=data);
        plt.xlabel('HTTPS')
        plt.ylabel('Count');
        st.pyplot()
    else:
        st.info("Please log in to access the application")

if __name__ == "__main__":
    main()
