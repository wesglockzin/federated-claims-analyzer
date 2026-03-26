#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Script Name : saml_settings.py
# Description : 
# Author      : Wes Glockzin
# Version     : 3.10 (Dynamic Base URL)
# License     : MIT
# -----------------------------------------------------------------------------
# saml_settings.py
from pathlib import Path
import os

# --- Base Directory ---
SCRIPT_DIR = Path(__file__).resolve().parent

# --- Configuration: Base URL (Local vs Cloud) ---
# Must match logic in main app logic
BASE_URL = os.environ.get("APP_BASE_URL", "https://localhost:8080").rstrip('/')

def read_file_content(file_name):
    """Helper function to read the content of a file."""
    try:
        with open(SCRIPT_DIR / file_name, 'r') as f:
            return f.read()
    except FileNotFoundError:
        print(f"ERROR: File '{file_name}' not found. Make sure it's in the root directory.")
        return ""

def get_sp_certs(idp_key):
    """Determines which SP cert/key pair to use based on the IdP key."""
    if 'cucm' in idp_key:
        return read_file_content('saml_tester_cucm.cert'), read_file_content('saml_tester_cucm.key')
    # Default to the primary certs for all others (SAML Test App #1 and OIDC)
    return read_file_content('saml_tester.cert'), read_file_content('saml_tester.key')


# --- Identity Provider (IdP) Configurations ---
IDP_CONFIGS = {
    # --- Existing Okta Configurations (SAML Test App #1) ---
    "okta_dev": {
        "entityId": "http://www.okta.com/YOUR_OKTA_APP_ID",
        "singleSignOnService": {
            "url": "https://idp-dev.example.com/app/your-org_samltesterapp_1/YOUR_OKTA_APP_ID/sso/saml"
        },
        "x509cert": """# Replace with your IdP's x509 certificate"""
    },
    # --- Okta Production SAML Configuration (SAML Test App #1) ---
    "okta_prod": {
        "entityId": "http://www.okta.com/YOUR_OKTA_APP_ID",
        "singleSignOnService": {
            "url": "https://idp.example.com/app/your-org_samltestapp1_1/YOUR_OKTA_APP_ID/sso/saml"
        },
        "x509cert": """# Replace with your IdP's x509 certificate"""
    },
    # --- Okta CUCM SAML Configuration ---
    "okta_cucm": {
        "entityId": "http://www.okta.com/YOUR_OKTA_APP_ID",
        "singleSignOnService": {
            "url": "https://idp-dev.example.com/app/your-org_cucmdev_1/YOUR_OKTA_APP_ID/sso/saml"
        },
        "x509cert": """# Replace with your IdP's x509 certificate"""
    },
    # --- Existing ADFS Configurations (SAML Test App #1) ---
    "adfs_dev": {
        "entityId": "http://adfs-dev.example.com/adfs/services/trust",
        "singleSignOnService": {
            "url": "https://adfs-dev.example.com/adfs/ls/"
        },
        "x509cert": """# Replace with your IdP's x509 certificate"""
    },
    "adfs_prod": {
        "entityId": "http://adfs.example.com/adfs/services/trust",
        "singleSignOnService": {
            "url": "https://adfs.example.com/adfs/ls/"
        },
        "x509cert": """# Replace with your IdP's x509 certificate"""
    },
    # --- NEW ADFS CUCM SAML Configuration ---
    "adfs_cucm": {
        "entityId": "https://cucm.example.com/ssosp/saml/metadata",
        "singleSignOnService": {
            "url": "https://adfs-dev.example.com/adfs/ls/"
        },
        "x509cert": """# Replace with your IdP's x509 certificate"""
    }
}

def get_saml_settings(idp_key):
    """
    Dynamically builds the settings dictionary required by the python3-saml library.
    """
    if idp_key not in IDP_CONFIGS:
        raise ValueError(f"Invalid IdP key provided: {idp_key}")

    # The SP must know which IdP to contact for the ACS URL.
    idp_name = idp_key.split('_')[0]
    
    # Select the correct SP cert/key pair based on the IdP key
    sp_x509cert, sp_privateKey = get_sp_certs(idp_key)
    
    # Determine the SP Entity ID based on the application type
    is_cucm_app = 'cucm' in idp_key
    sp_entity_id = IDP_CONFIGS[idp_key]["entityId"] if is_cucm_app else "saml.tester"


    # Define settings for our application (the Service Provider)
    # Uses the dynamic BASE_URL
    sp_config = {
        "entityId": sp_entity_id,
        "assertionConsumerService": {
            "url": f"{BASE_URL}/{idp_name}/saml/callback",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        },
        "singleLogoutService": {
            "url": f"{BASE_URL}/{idp_name}/saml/sls",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        "x509cert": sp_x509cert,
        "privateKey": sp_privateKey
    }

    # --- CUSTOM SECURITY CONFIGURATION LOGIC ---
    # Define security settings
    security_config = {
        "authnRequestsSigned": True,
        "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        "wantAssertionsSigned": True, 
    }
    
    # ADFS Quirk Fix: Add lowercase URL encoding flag to fix signature validation.
    if idp_name == 'adfs':
        security_config["lowercase_urlencoding"] = True

    # Combine all parts into the final settings dictionary
    settings = {
        "strict": True,
        "debug": True,
        "sp": sp_config,
        "idp": IDP_CONFIGS[idp_key],
        "security": security_config
    }

    return settings