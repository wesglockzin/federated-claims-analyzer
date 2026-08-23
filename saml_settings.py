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
        "entityId": "http://www.okta.com/exkEXAMPLE00EXAMPLE0",
        "singleSignOnService": {
            "url": "https://host.example.gov/[redacted-path]"
        },
        "x509cert": """-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgIUI+rJR2H1qwlEc8nPr2wPLz8Tm4UwDQYJKoZIhvcNAQELBQAwSjEgMB4G
A1UEAwwXZXhhbXBsZS1pZHAuZXhhbXBsZS5jb20xFDASBgNVBAoMC0V4YW1wbGUgT3JnMRAwDgYD
VQQLDAdFeGFtcGxlMB4XDTI2MDgyMzE2MDAzOFoXDTM2MDgyMDE2MDAzOFowSjEgMB4GA1UEAwwX
ZXhhbXBsZS1pZHAuZXhhbXBsZS5jb20xFDASBgNVBAoMC0V4YW1wbGUgT3JnMRAwDgYDVQQLDAdF
eGFtcGxlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwvUSvRr1alwBJFkoAYzRG4vq
CuoE0Td3biEhVw7I3bfBd6wRKhDyRRG2LDjD0RQ7XNjmA7AMCBP3VPJq2bDfrCs2QZDXpiW98fbr
9KIwCIWyhgZ7y27WfCi0yNX/mmZZ45mwccGfBYAMZZ88+KWqmhMLJCHUSzuSTcexBOkeev5P3Z/X
Al+9pSlcjRfEvg27KL13Cg8ZPcFWDVn4zOMJ3LVmMZAccs5Og3xwuibzUwPw4w+sazFIEKnB7Lco
9Qo+hpw6SsAVsTvRQtKUSY6WxpGD/7LR8QC7CV2htixH9xfzA516AHcN0Erc67E+NF3RskVtYaXQ
TsYqYnQWlCjiowIDAQABo1MwUTAdBgNVHQ4EFgQUTkhYxvJoj+kd1eTHGLm/5mrNYzIwHwYDVR0j
BBgwFoAUTkhYxvJoj+kd1eTHGLm/5mrNYzIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsF
AAOCAQEAXmb43AlgcoKjTTIx582LqwUZJkO4KoWdbhKxojCzspa401O0BISordRBB3mqrGYBi/1S
Em690y2xTmn49ee2BSdiB4LShbnXAtTWGCUVXr1570y6rYHOCRxg3mwpUhurWhl4oeVQAX4ziDwx
+aLBKqlCTUeuT5wRUYaa5MeZRVDvwDkUtJCVJfhpKcIS5J5SOJYU2Sl6MV3RW/op2mNFsgyGlYkX
TIac5LYJTwmpgecIPRdww/ir0SIAtvvymAiovxU2VWx47rebe7PcEtAxDKNs9KgM7za+Yb14+X8m
j5neLe3GrstpiG85oK2TbNHAMAly0fzmRucGzS/HlQ0GhA==
-----END CERTIFICATE-----"""
    },
    # --- Okta Staging SAML Configuration (SAML Test App #1) ---
    "okta_stg": {
        "entityId": "http://www.okta.com/exkEXAMPLE00EXAMPLE0",
        "singleSignOnService": {
            "url": "https://host.example.gov/[redacted-path]"
        },
        "x509cert": """-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgIUI+rJR2H1qwlEc8nPr2wPLz8Tm4UwDQYJKoZIhvcNAQELBQAwSjEgMB4G
A1UEAwwXZXhhbXBsZS1pZHAuZXhhbXBsZS5jb20xFDASBgNVBAoMC0V4YW1wbGUgT3JnMRAwDgYD
VQQLDAdFeGFtcGxlMB4XDTI2MDgyMzE2MDAzOFoXDTM2MDgyMDE2MDAzOFowSjEgMB4GA1UEAwwX
ZXhhbXBsZS1pZHAuZXhhbXBsZS5jb20xFDASBgNVBAoMC0V4YW1wbGUgT3JnMRAwDgYDVQQLDAdF
eGFtcGxlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwvUSvRr1alwBJFkoAYzRG4vq
CuoE0Td3biEhVw7I3bfBd6wRKhDyRRG2LDjD0RQ7XNjmA7AMCBP3VPJq2bDfrCs2QZDXpiW98fbr
9KIwCIWyhgZ7y27WfCi0yNX/mmZZ45mwccGfBYAMZZ88+KWqmhMLJCHUSzuSTcexBOkeev5P3Z/X
Al+9pSlcjRfEvg27KL13Cg8ZPcFWDVn4zOMJ3LVmMZAccs5Og3xwuibzUwPw4w+sazFIEKnB7Lco
9Qo+hpw6SsAVsTvRQtKUSY6WxpGD/7LR8QC7CV2htixH9xfzA516AHcN0Erc67E+NF3RskVtYaXQ
TsYqYnQWlCjiowIDAQABo1MwUTAdBgNVHQ4EFgQUTkhYxvJoj+kd1eTHGLm/5mrNYzIwHwYDVR0j
BBgwFoAUTkhYxvJoj+kd1eTHGLm/5mrNYzIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsF
AAOCAQEAXmb43AlgcoKjTTIx582LqwUZJkO4KoWdbhKxojCzspa401O0BISordRBB3mqrGYBi/1S
Em690y2xTmn49ee2BSdiB4LShbnXAtTWGCUVXr1570y6rYHOCRxg3mwpUhurWhl4oeVQAX4ziDwx
+aLBKqlCTUeuT5wRUYaa5MeZRVDvwDkUtJCVJfhpKcIS5J5SOJYU2Sl6MV3RW/op2mNFsgyGlYkX
TIac5LYJTwmpgecIPRdww/ir0SIAtvvymAiovxU2VWx47rebe7PcEtAxDKNs9KgM7za+Yb14+X8m
j5neLe3GrstpiG85oK2TbNHAMAly0fzmRucGzS/HlQ0GhA==
-----END CERTIFICATE-----"""
    },
    # --- Okta Production SAML Configuration (SAML Test App #1) ---
    "okta_prod": {
        "entityId": "http://www.okta.com/exkEXAMPLE00EXAMPLE0",
        "singleSignOnService": {
            "url": "https://host.example.gov/[redacted-path]"
        },
        "x509cert": """-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgIUI+rJR2H1qwlEc8nPr2wPLz8Tm4UwDQYJKoZIhvcNAQELBQAwSjEgMB4G
A1UEAwwXZXhhbXBsZS1pZHAuZXhhbXBsZS5jb20xFDASBgNVBAoMC0V4YW1wbGUgT3JnMRAwDgYD
VQQLDAdFeGFtcGxlMB4XDTI2MDgyMzE2MDAzOFoXDTM2MDgyMDE2MDAzOFowSjEgMB4GA1UEAwwX
ZXhhbXBsZS1pZHAuZXhhbXBsZS5jb20xFDASBgNVBAoMC0V4YW1wbGUgT3JnMRAwDgYDVQQLDAdF
eGFtcGxlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwvUSvRr1alwBJFkoAYzRG4vq
CuoE0Td3biEhVw7I3bfBd6wRKhDyRRG2LDjD0RQ7XNjmA7AMCBP3VPJq2bDfrCs2QZDXpiW98fbr
9KIwCIWyhgZ7y27WfCi0yNX/mmZZ45mwccGfBYAMZZ88+KWqmhMLJCHUSzuSTcexBOkeev5P3Z/X
Al+9pSlcjRfEvg27KL13Cg8ZPcFWDVn4zOMJ3LVmMZAccs5Og3xwuibzUwPw4w+sazFIEKnB7Lco
9Qo+hpw6SsAVsTvRQtKUSY6WxpGD/7LR8QC7CV2htixH9xfzA516AHcN0Erc67E+NF3RskVtYaXQ
TsYqYnQWlCjiowIDAQABo1MwUTAdBgNVHQ4EFgQUTkhYxvJoj+kd1eTHGLm/5mrNYzIwHwYDVR0j
BBgwFoAUTkhYxvJoj+kd1eTHGLm/5mrNYzIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsF
AAOCAQEAXmb43AlgcoKjTTIx582LqwUZJkO4KoWdbhKxojCzspa401O0BISordRBB3mqrGYBi/1S
Em690y2xTmn49ee2BSdiB4LShbnXAtTWGCUVXr1570y6rYHOCRxg3mwpUhurWhl4oeVQAX4ziDwx
+aLBKqlCTUeuT5wRUYaa5MeZRVDvwDkUtJCVJfhpKcIS5J5SOJYU2Sl6MV3RW/op2mNFsgyGlYkX
TIac5LYJTwmpgecIPRdww/ir0SIAtvvymAiovxU2VWx47rebe7PcEtAxDKNs9KgM7za+Yb14+X8m
j5neLe3GrstpiG85oK2TbNHAMAly0fzmRucGzS/HlQ0GhA==
-----END CERTIFICATE-----"""
    },
    # --- Okta CUCM SAML Configuration ---
    "okta_cucm": {
        "entityId": "http://www.okta.com/exkEXAMPLE00EXAMPLE0", 
        "singleSignOnService": {
            "url": "https://host.example.gov/[redacted-path]"
        },
        "x509cert": """-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgIUI+rJR2H1qwlEc8nPr2wPLz8Tm4UwDQYJKoZIhvcNAQELBQAwSjEgMB4G
A1UEAwwXZXhhbXBsZS1pZHAuZXhhbXBsZS5jb20xFDASBgNVBAoMC0V4YW1wbGUgT3JnMRAwDgYD
VQQLDAdFeGFtcGxlMB4XDTI2MDgyMzE2MDAzOFoXDTM2MDgyMDE2MDAzOFowSjEgMB4GA1UEAwwX
ZXhhbXBsZS1pZHAuZXhhbXBsZS5jb20xFDASBgNVBAoMC0V4YW1wbGUgT3JnMRAwDgYDVQQLDAdF
eGFtcGxlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwvUSvRr1alwBJFkoAYzRG4vq
CuoE0Td3biEhVw7I3bfBd6wRKhDyRRG2LDjD0RQ7XNjmA7AMCBP3VPJq2bDfrCs2QZDXpiW98fbr
9KIwCIWyhgZ7y27WfCi0yNX/mmZZ45mwccGfBYAMZZ88+KWqmhMLJCHUSzuSTcexBOkeev5P3Z/X
Al+9pSlcjRfEvg27KL13Cg8ZPcFWDVn4zOMJ3LVmMZAccs5Og3xwuibzUwPw4w+sazFIEKnB7Lco
9Qo+hpw6SsAVsTvRQtKUSY6WxpGD/7LR8QC7CV2htixH9xfzA516AHcN0Erc67E+NF3RskVtYaXQ
TsYqYnQWlCjiowIDAQABo1MwUTAdBgNVHQ4EFgQUTkhYxvJoj+kd1eTHGLm/5mrNYzIwHwYDVR0j
BBgwFoAUTkhYxvJoj+kd1eTHGLm/5mrNYzIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsF
AAOCAQEAXmb43AlgcoKjTTIx582LqwUZJkO4KoWdbhKxojCzspa401O0BISordRBB3mqrGYBi/1S
Em690y2xTmn49ee2BSdiB4LShbnXAtTWGCUVXr1570y6rYHOCRxg3mwpUhurWhl4oeVQAX4ziDwx
+aLBKqlCTUeuT5wRUYaa5MeZRVDvwDkUtJCVJfhpKcIS5J5SOJYU2Sl6MV3RW/op2mNFsgyGlYkX
TIac5LYJTwmpgecIPRdww/ir0SIAtvvymAiovxU2VWx47rebe7PcEtAxDKNs9KgM7za+Yb14+X8m
j5neLe3GrstpiG85oK2TbNHAMAly0fzmRucGzS/HlQ0GhA==
-----END CERTIFICATE-----"""
    },
    # --- Existing ADFS Configurations (SAML Test App #1) ---
    "adfs_dev": {
        "entityId": "https://host.example.gov/[redacted-path]",
        "singleSignOnService": {
            "url": "https://host.example.gov/[redacted-path]"
        },
        "x509cert": """-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgIUI+rJR2H1qwlEc8nPr2wPLz8Tm4UwDQYJKoZIhvcNAQEL
BQAwSjEgMB4GA1UEAwwXZXhhbXBsZS1pZHAuZXhhbXBsZS5jb20xFDASBgNVBAoM
C0V4YW1wbGUgT3JnMRAwDgYDVQQLDAdFeGFtcGxlMB4XDTI2MDgyMzE2MDAzOFoX
DTM2MDgyMDE2MDAzOFowSjEgMB4GA1UEAwwXZXhhbXBsZS1pZHAuZXhhbXBsZS5j
b20xFDASBgNVBAoMC0V4YW1wbGUgT3JnMRAwDgYDVQQLDAdFeGFtcGxlMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwvUSvRr1alwBJFkoAYzRG4vqCuoE
0Td3biEhVw7I3bfBd6wRKhDyRRG2LDjD0RQ7XNjmA7AMCBP3VPJq2bDfrCs2QZDX
piW98fbr9KIwCIWyhgZ7y27WfCi0yNX/mmZZ45mwccGfBYAMZZ88+KWqmhMLJCHU
SzuSTcexBOkeev5P3Z/XAl+9pSlcjRfEvg27KL13Cg8ZPcFWDVn4zOMJ3LVmMZAc
cs5Og3xwuibzUwPw4w+sazFIEKnB7Lco9Qo+hpw6SsAVsTvRQtKUSY6WxpGD/7LR
8QC7CV2htixH9xfzA516AHcN0Erc67E+NF3RskVtYaXQTsYqYnQWlCjiowIDAQAB
o1MwUTAdBgNVHQ4EFgQUTkhYxvJoj+kd1eTHGLm/5mrNYzIwHwYDVR0jBBgwFoAU
TkhYxvJoj+kd1eTHGLm/5mrNYzIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAXmb43AlgcoKjTTIx582LqwUZJkO4KoWdbhKxojCzspa401O0BISo
rdRBB3mqrGYBi/1SEm690y2xTmn49ee2BSdiB4LShbnXAtTWGCUVXr1570y6rYHO
CRxg3mwpUhurWhl4oeVQAX4ziDwx+aLBKqlCTUeuT5wRUYaa5MeZRVDvwDkUtJCV
JfhpKcIS5J5SOJYU2Sl6MV3RW/op2mNFsgyGlYkXTIac5LYJTwmpgecIPRdww/ir
0SIAtvvymAiovxU2VWx47rebe7PcEtAxDKNs9KgM7za+Yb14+X8mj5neLe3Grstp
iG85oK2TbNHAMAly0fzmRucGzS/HlQ0GhA==
-----END CERTIFICATE-----"""
    },
    "adfs_prod": {
        "entityId": "https://host.example.gov/[redacted-path]",
        "singleSignOnService": {
            "url": "https://host.example.gov/[redacted-path]"
        },
        "x509cert": """-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgIUI+rJR2H1qwlEc8nPr2wPLz8Tm4UwDQYJKoZIhvcNAQEL
BQAwSjEgMB4GA1UEAwwXZXhhbXBsZS1pZHAuZXhhbXBsZS5jb20xFDASBgNVBAoM
C0V4YW1wbGUgT3JnMRAwDgYDVQQLDAdFeGFtcGxlMB4XDTI2MDgyMzE2MDAzOFoX
DTM2MDgyMDE2MDAzOFowSjEgMB4GA1UEAwwXZXhhbXBsZS1pZHAuZXhhbXBsZS5j
b20xFDASBgNVBAoMC0V4YW1wbGUgT3JnMRAwDgYDVQQLDAdFeGFtcGxlMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwvUSvRr1alwBJFkoAYzRG4vqCuoE
0Td3biEhVw7I3bfBd6wRKhDyRRG2LDjD0RQ7XNjmA7AMCBP3VPJq2bDfrCs2QZDX
piW98fbr9KIwCIWyhgZ7y27WfCi0yNX/mmZZ45mwccGfBYAMZZ88+KWqmhMLJCHU
SzuSTcexBOkeev5P3Z/XAl+9pSlcjRfEvg27KL13Cg8ZPcFWDVn4zOMJ3LVmMZAc
cs5Og3xwuibzUwPw4w+sazFIEKnB7Lco9Qo+hpw6SsAVsTvRQtKUSY6WxpGD/7LR
8QC7CV2htixH9xfzA516AHcN0Erc67E+NF3RskVtYaXQTsYqYnQWlCjiowIDAQAB
o1MwUTAdBgNVHQ4EFgQUTkhYxvJoj+kd1eTHGLm/5mrNYzIwHwYDVR0jBBgwFoAU
TkhYxvJoj+kd1eTHGLm/5mrNYzIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAXmb43AlgcoKjTTIx582LqwUZJkO4KoWdbhKxojCzspa401O0BISo
rdRBB3mqrGYBi/1SEm690y2xTmn49ee2BSdiB4LShbnXAtTWGCUVXr1570y6rYHO
CRxg3mwpUhurWhl4oeVQAX4ziDwx+aLBKqlCTUeuT5wRUYaa5MeZRVDvwDkUtJCV
JfhpKcIS5J5SOJYU2Sl6MV3RW/op2mNFsgyGlYkXTIac5LYJTwmpgecIPRdww/ir
0SIAtvvymAiovxU2VWx47rebe7PcEtAxDKNs9KgM7za+Yb14+X8mj5neLe3Grstp
iG85oK2TbNHAMAly0fzmRucGzS/HlQ0GhA==
-----END CERTIFICATE-----"""
    },
    # --- NEW ADFS CUCM SAML Configuration ---
    "adfs_cucm": {
        "entityId": "https://host.example.gov/[redacted-path]", 
        "singleSignOnService": {
            "url": "https://host.example.gov/[redacted-path]"
        },
        "x509cert": """-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgIUI+rJR2H1qwlEc8nPr2wPLz8Tm4UwDQYJKoZIhvcNAQEL
BQAwSjEgMB4GA1UEAwwXZXhhbXBsZS1pZHAuZXhhbXBsZS5jb20xFDASBgNVBAoM
C0V4YW1wbGUgT3JnMRAwDgYDVQQLDAdFeGFtcGxlMB4XDTI2MDgyMzE2MDAzOFoX
DTM2MDgyMDE2MDAzOFowSjEgMB4GA1UEAwwXZXhhbXBsZS1pZHAuZXhhbXBsZS5j
b20xFDASBgNVBAoMC0V4YW1wbGUgT3JnMRAwDgYDVQQLDAdFeGFtcGxlMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwvUSvRr1alwBJFkoAYzRG4vqCuoE
0Td3biEhVw7I3bfBd6wRKhDyRRG2LDjD0RQ7XNjmA7AMCBP3VPJq2bDfrCs2QZDX
piW98fbr9KIwCIWyhgZ7y27WfCi0yNX/mmZZ45mwccGfBYAMZZ88+KWqmhMLJCHU
SzuSTcexBOkeev5P3Z/XAl+9pSlcjRfEvg27KL13Cg8ZPcFWDVn4zOMJ3LVmMZAc
cs5Og3xwuibzUwPw4w+sazFIEKnB7Lco9Qo+hpw6SsAVsTvRQtKUSY6WxpGD/7LR
8QC7CV2htixH9xfzA516AHcN0Erc67E+NF3RskVtYaXQTsYqYnQWlCjiowIDAQAB
o1MwUTAdBgNVHQ4EFgQUTkhYxvJoj+kd1eTHGLm/5mrNYzIwHwYDVR0jBBgwFoAU
TkhYxvJoj+kd1eTHGLm/5mrNYzIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAXmb43AlgcoKjTTIx582LqwUZJkO4KoWdbhKxojCzspa401O0BISo
rdRBB3mqrGYBi/1SEm690y2xTmn49ee2BSdiB4LShbnXAtTWGCUVXr1570y6rYHO
CRxg3mwpUhurWhl4oeVQAX4ziDwx+aLBKqlCTUeuT5wRUYaa5MeZRVDvwDkUtJCV
JfhpKcIS5J5SOJYU2Sl6MV3RW/op2mNFsgyGlYkXTIac5LYJTwmpgecIPRdww/ir
0SIAtvvymAiovxU2VWx47rebe7PcEtAxDKNs9KgM7za+Yb14+X8mj5neLe3Grstp
iG85oK2TbNHAMAly0fzmRucGzS/HlQ0GhA==
-----END CERTIFICATE-----"""
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
    # Also disable RequestedAuthnContext — ADFS returns NoAuthnContext if the session
    # auth context (e.g. WindowsAuthentication) doesn't exactly match the default
    # PasswordProtectedTransport that python3-saml sends when this is unset.
    if idp_name == 'adfs':
        security_config["lowercase_urlencoding"] = True
        security_config["requestedAuthnContext"] = False

    # Combine all parts into the final settings dictionary
    settings = {
        "strict": True,
        "debug": True,
        "sp": sp_config,
        "idp": IDP_CONFIGS[idp_key],
        "security": security_config
    }

    return settings