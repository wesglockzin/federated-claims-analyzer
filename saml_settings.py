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
        "entityId": "http://www.okta.com/exk158mkgksNtCrSE0j7",
        "singleSignOnService": {
            "url": "https://host.example.gov/[redacted-path]
        },
        "x509cert": """-----BEGIN CERTIFICATE-----
MIIDpDCCAoygAwIBAgIGAZg9zhbAMA0GCSqGSIb3DQEBCwUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi1zZW5hdGUxHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMjUwNzI0MTg1ODMzWhcNMzUwNzI0MTg1OTMzWjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtc2VuYXRlMRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
nnqCqnLvZs90/b9WYgMZNGpOFeQ5zjc1kH2XwEJxKb2z666MhQGPn6eUugabec0DIqsqvQlqTVEs
NlYhulCmOEY7A6vG44P9KI/5S4TCyTPOYsZldFabDjdYDtIcfHop+vN/KXxY+7zvhLeiFs1kXZJa
LLO46dZmUbhKoO2Ywn4ISlFXfkcg8LlZ7VX1Upbbh6qU2mk9Scn6om2ncWxrpRgkfPHmfnBBFHv8
Xmau/MkKG4rFu6FQLXIDfXVmWRwgb9lIw7gl7L4t7HTfLxZdjOdzKjLR9HNId910f6JQagK0/DSe
7pffI2cJHhvdRCbANwUFZMSKJ1em8/PcmSin5QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBImWIX
HZ4vMSF+L72oHbziCdP8jhwjsMJQNcP8rHg5eyRvPyWv5OgO8lScOpW3Y4wGQjAXq+Y3MOiwyhpi
CfuWzu16rX2NkmFssGm2DuZJbrLPkiiBPNjUoe2R9vTPN59YDaYHqRobnNNyImA9VaLFf45FlO90
QAOKPF/dNmUfDef9OiRYVREvN9D3/inpXlm5WMauP35srSIFh0Hb8ZQewYjHLMs2f/jpnZAiMAHq
ksrmFBvkPuq+kvvyH8VlEXn/4ZD2psOeG5z2/p3PZ8n/GiYM8JDypu1E+mXj/xNHiHn0120EUk4k
T60aBV/DZYno+5i5YPARBZbLtb8hPm5D
-----END CERTIFICATE-----"""
    },
    # --- Okta Staging SAML Configuration (SAML Test App #1) ---
    "okta_stg": {
        "entityId": "http://www.okta.com/exk1k05a9b7hUhwKT0j7",
        "singleSignOnService": {
            "url": "https://host.example.gov/[redacted-path]
        },
        "x509cert": """-----BEGIN CERTIFICATE-----
MIIDrDCCApSgAwIBAgIGAZy/wsDbMA0GCSqGSIb3DQEBCwUAMIGWMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxFzAVBgNVBAMMDnN0YWdpbmctc2VuYXRlMRwwGgYJKoZIhvcN
AQkBFg1pbmZvQG9rdGEuY29tMB4XDTI2MDMwNTIwNDc1N1oXDTM2MDMwNTIwNDg1N1owgZYxCzAJ
BgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ0w
CwYDVQQKDARPa3RhMRQwEgYDVQQLDAtTU09Qcm92aWRlcjEXMBUGA1UEAwwOc3RhZ2luZy1zZW5h
dGUxHDAaBgkqhkiG9w0BCQEWDWluZm9Ab2t0YS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDKwNg6Jj5gyyX2rTwZh9UhsKmTX+Y60FCF/07th+pDaZLntVNZkp6IIPZ+SCAIWy+8
tDEv8dKrtEPYl8lmTiXgHasj/orLecFZGwUPnhkt+S4PzJ7ONkYvU3MCt07rtjX6JWhLRWUctz0V
U3SPW0ijqODlV1hOT1RtnJY5xRSsnHHaPhanigjR4a4/IEKDQh6MOU48TB/+hX6HOBqZkT9IyoaS
cR3ThWfPCGh1rSlTDJoIAww+8P3yDht0WgFUQ3Ii0Ps1Pn0eX86q9KgvzBEV1diriePtw80jUbSY
X0eECEWAlyEcGMmg5PNCNGGj3ulgOb3o44Rre2ZsxgsSWjzNAgMBAAEwDQYJKoZIhvcNAQELBQAD
ggEBADF5WqX8vmLr5iyKK7ps0Ey1DyRf9S0QZf3PO9Qi4JnVdY5UHOOZ5+eF6PMdankerj+o21Cr
gQSn9j7LnfC9UaHF2b0lZls5Dzw5bADs4YkfygZdflDZKuVFGre+6mNIeMlP2EUSivKoNWztk7Eb
CO9yMx7dG+vYNaDJJc53kir63KR43VNQv74jGwLfAu5dYfmzTDF/zlVYDjXrTjEN/6kM4F7aQsv0
PYaUUSeZAvrfjMHenruAEEIs90mxHu3P36RSdqhY44++daObrm0Bs3GSSn8C5KJlQzWd4wX0RxL9
EZxcaPNr4GejYPgN3dki78+dn1N9e75us0WY1jAx0xY=
-----END CERTIFICATE-----"""
    },
    # --- Okta Production SAML Configuration (SAML Test App #1) ---
    "okta_prod": {
        "entityId": "http://www.okta.com/exk1fiyrqm281w9n40j7",
        "singleSignOnService": {
            "url": "https://host.example.gov/[redacted-path]
        },
        "x509cert": """-----BEGIN CERTIFICATE-----
MIIDnDCCAoSgAwIBAgIGAZszV484MA0GCSqGSIb3DQEBCwUAMIGOMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxDzANBgNVBAMMBnNlbmF0ZTEcMBoGCSqGSIb3DQEJARYNaW5m
b0Bva3RhLmNvbTAeFw0yNTEyMTgyMTIxMTRaFw0zNTEyMTgyMTIyMTRaMIGOMQswCQYDVQQGEwJV
UzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwE
T2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxDzANBgNVBAMMBnNlbmF0ZTEcMBoGCSqGSIb3DQEJ
ARYNaW5mb0Bva3RhLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKn6ipV9vnOD
WLJ3WDydMlLS01Jp+xAWJqCVgY/TNGbKZ+ctN8teMVqq/+iPJErkkFH5FXHI0bnl0+QV2jMrw2Uv
Z8avL9QEtImWBvh+i6uP1S6IHcda4yF9yKcTwLLLydMKpL45u32RlZTJSO/GRZdDqOGwWFfjP+oq
ThkdQT3Eut3bji46PeHa5KT8seOj8KEnTDQ1utMqkJTbGXbiurHvl76Ayecy31ZgsKT3hH3Qq1zW
LcJsCMGoKfcWPauvfyf7r4EKDudgK3SocKtdVFzaMLyR1efoMRuMEy94Bu1Nh/2DTMEopa4i8P0P
TM672XdYR+qzPX0zYOhMShFKwoUCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAkK3k0hlqrXqXoqBm
NnXOV6Z2zLaI1fvT4/cHko45w/jLBMsQ3nXZgDjodf8PZzvHI6sikT4p06F2xGVn6XxLdIX3W7hz
5IT0xu1vdcmXuyVfjymEV57p14M8zu+N14iZqJSQuHipVXeA0q1pdCNzKDxM4TQVV1eyR1WhK1bY
SwRQ8winPUK7OZr6lNcTLVRNbilUjf2+7MISDg37IVeokkJzglUwuB0cNSm+M789s98D1DEwNK0o
9w74OlQay2Hgt13kGqs7Nnr0HrMUjIVvKBqj4Va24cEadLzvW39yC3wDMT010irfp9iPtP/VfrjR
u9P8Nt31YILodG7o7bpv7g==
-----END CERTIFICATE-----"""
    },
    # --- Okta CUCM SAML Configuration ---
    "okta_cucm": {
        "entityId": "http://www.okta.com/exk1akh82ekyCeCGH0j7", 
        "singleSignOnService": {
            "url": "https://host.example.gov/[redacted-path]
        },
        "x509cert": """-----BEGIN CERTIFICATE-----
MIIDpDCCAoygAwIBAgIGAZmgyCuJMA0GCSqGSIb3DQEBCwUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi1zZW5hdGUxHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMjUxMDAxMTcxNzE2WhcNMzUxMDAxMTcxODE2WjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtc2VuYXRlMRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
6AX0pYtn+fX0HFHK2bhmlG+iivkqDaelafYwFwpWGcVCMNqMRh5+0o6fkr3bwO1avufZuo3lMvEq
7o3scJmguwCj5tKdJjCqKeaLU00me9R6aAxM2ra0GNRaVrjgM/n+V6HuCOV9jIXRxaa+wBFP3EYe
xgKk/c9bVv/jJTby9Hz0G+4onMRCv8tng+rAWmATUNz3QzEmC6uIIDi5olb0HUCWpEcj3GmHAeY5
hnCa+urOQsuZtcgkHCsfc/U6cyfznRhaFGQ3NGX9nQnRn3+A6/9Ca4chsMXbRCPxWHJXTMzGnuT1
wbUXrDtC4gb4l53/ZP2dq6Q3Uy1TH6VxdE4kSQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQDLRQfj
yLeKA3/Fgh+cygA/V5qtdyvRmUnZHd1cRkD/IvGsqg5YJFkhBW/FaSUrvn1qPb+BR/HEZGkq5pLD
CiwB2pDa44GZ2rnEOOXxaQR1GNnOors3tMp8nRrM9G+hKGTVIAF2ioBTH6XoBxzUpr/xI5OmjcF4
OLQp11EzqXB/OCm/fi4+1mG4dihMSENEXQzT5cRWHNhNpt95QzBVVBI3/iRrQg5Jg+0KIdWEg5SC
JGAQqPdDFWLkbQ63Y5zQXBmwF7qqbEly2ku4xvbsqaGz13DFJtdP2NZ9SFv0W+6PQbU2V/2/N7A1
6gr5sI30uP9YO8Wd0tHLJLKfH3u8X9FB
-----END CERTIFICATE-----"""
    },
    # --- Existing ADFS Configurations (SAML Test App #1) ---
    "adfs_dev": {
        "entityId": "https://host.example.gov/[redacted-path]
        "singleSignOnService": {
            "url": "https://host.example.gov/[redacted-path]
        },
        "x509cert": """-----BEGIN CERTIFICATE-----
MIIC3jCCAcagAwIBAgIQRUVr983eX5tCKvV0aJlHrDANBgkqhkiG9w0BAQsFADAr
MSkwJwYDVQQDEyBBREZTIFNpZ25pbmcgLSBhZGZzLnNlbmF0ZWRldi51czAeFw0x
NzA0MDkwMTUyMzVaFw0yNzA0MDcwMTUyMzVaMCsxKTAnBgNVBAMTIEFERlMgU2ln
bmluZyAtIGFkZnMuc2VuYXRlZGV2LnVzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAx1yWXCfwb7YjV/erkDG5Uzouki+1ifwE5PIQ3tiBpLM8UA9b37zS
ZrtawzzaaAL7qextGGiGkGdEvGYpA543nt+G747VhTznS24z7/56pNRWc3KTvDim
bvHgTpxxXAMz1kXq+VHCp6hDG3ItfwQ8sWkfaluILTL7hn38XLnV60J/CT9LuVzu
TlucyRiNUdcu8/yqoAfqO+EBIsqpuPeDfCcrX7b/I8/dnaKni9j1BmFmQO5UFTiR
B/pREIXLNIXElofHzUw6AqYReREAhxYQhA9dwkvqf+ZCnnXJWvayXlARHaPX2aM4
xL/91tA8zkFBaWfKy0lWD+7GXT5rC4vjNQIDAQABMA0GCSqGSIb3DQEBCwUAA4IB
AQAvOW9eGx0eJkiclusq734n/X/4TNO8p5CMJIl9vGuahcnOboWvbxDYnac/6A/O
jVtTQEJxS/TLKPWoTCi5jv4kAviaF9PypiLmRPFQclWxha5mNZdKHDjvYJ2GNRWU
lZCyk5gl5xh5M+MJGajNt5w0cEEN9vzkvX1RTnMVb0xnW7I1jH5nCMlj/03BsQQp
c5oINwBkGrRlsUWbPkj4y2HIaEsznMHPacOzYmqcDlZF2AhzFJJU+ld0ue8lYGKT
0xps13Zzv/UeqwZNhaT3Y8tO9/ZjTebQ21bwgeDmGoGoRVAUaQQmEHdml5Rr/hMn
PNa6Z8z3EgLbD2GlfTQ4iccW
-----END CERTIFICATE-----"""
    },
    "adfs_prod": {
        "entityId": "https://host.example.gov/[redacted-path]
        "singleSignOnService": {
            "url": "https://host.example.gov/[redacted-path]
        },
        "x509cert": """-----BEGIN CERTIFICATE-----
MIIC2jCCAcKgAwIBAgIQQVnPw1Yk+L1N/g7DMmOOAjANBgkqhkiG9w0BAQsFADAp
MScwJQYDVQQDEx5BREZTIFNpZ25pbmcgLSBhZGZzLnNlbmF0ZS5nb3YwHhcNMTcw
NjEwMTY1NjE4WhcNMjcwNjA4MTY1NjE4WjApMScwJQYDVQQDEx5BREZTIFNpZ25p
bmcgLSBhZGZzLnNlbmF0ZS5nb3YwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQD0CcSlNI3GbcsUIz9UB2wbB7Z1LumoEo/RrSIMC0QNwZdOUDXk7Jt2EiZW
ngqNtF6sv0kFm4X4EGmXAssanPl1TAcwWWmOv4FTD1w8AjgetZh92Cwb5KfoCbLR
T78P61Sjjbq1Pvu4YFA3L7Rk8bqIRyw9c3hSrTRwBU7TTYLhOWi0sn3T0SIZ3czx
1WDpBlkDmmU0e09DHdJGdK5AGufofT00307ISqx/Ndc3YNoRr2A8/ZmK7C/48+dd
MJCqb/aE7/uFYyFSHatqgNMV6qbnw9RlqqrD4YKEV7Yxfi57GeC0QSnBgoi9eKvB
UeRzQySEJo7deUCYfRp1bh3C2BedAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAMYw
D0J6d2z3XkYhuf48RZ3PkLfW/7en8pgDisDrTpeYKjp/E3ynZa4Qdyj8TEsiFR/9
bGGTHPxln/E1B8h8hXtXtMRm5A7ptKq5h5iqDF9WScOsfHHln2IKWWAets/sc4Iq
xX82gQrU5UTLuN2vSw02osJxte/2tNUViUEfght+ICuYv7rzV4IsZz8YB+Blxt7D
JCTyjBunjxjbvxI57SJCV2ZuiRoId88jXkc8QvtwdHw2Fq4mEcEKSeCptXYjT9jw
LTT6D21q5jwjdYjL5VbnPEJakGA0h5OG+xdaJJWn55ky10LtaBctedc/eFA2xusd
G6qXTEW4GkbJxL4byMI=
-----END CERTIFICATE-----"""
    },
    # --- NEW ADFS CUCM SAML Configuration ---
    "adfs_cucm": {
        "entityId": "https://host.example.gov/[redacted-path] 
        "singleSignOnService": {
            "url": "https://host.example.gov/[redacted-path]
        },
        "x509cert": """-----BEGIN CERTIFICATE-----
MIIC3jCCAcagAwIBAgIQRUVr983eX5tCKvV0aJlHrDANBgkqhkiG9w0BAQsFADAr
MSkwJwYDVQQDEyBBREZTIFNpZ25pbmcgLSBhZGZzLnNlbmF0ZWRldi51czAeFw0x
NzA0MDkwMTUyMzVaFw0yNzA0MDcwMTUyMzVaMCsxKTAnBgNVBAMTIEFERlMgU2ln
bmluZyAtIGFkZnMuc2VuYXRlZGV2LnVzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAx1yWXCfwb7YjV/erkDG5Uzouki+1ifwE5PIQ3tiBpLM8UA9b37zS
ZrtawzzaaAL7qextGGiGkGdEvGYpA543nt+G747VhTznS24z7/56pNRWc3KTvDim
bvHgTpxxXAMz1kXq+VHCp6hDG3ItfwQ8sWkfaluILTL7hn38XLnV60J/CT9LuVzu
TlucyRiNUdcu8/yqoAfqO+EBIsqpuPeDfCcrX7b/I8/dnaKni9j1BmFmQO5UFTiR
B/pREIXLNIXElofHzUw6AqYReREAhxYQhA9dwkvqf+ZCnnXJWvayXlARHaPX2aM4
xL/91tA8zkFBaWfKy0lWD+7GXT5rC4vjNQIDAQABMA0GCSqGSIb3DQEBCwUAA4IB
AQAvOW9eGx0eJkiclusq734n/X/4TNO8p5CMJIl9vGuahcnOboWvbxDYnac/6A/O
jVtTQEJxS/TLKPWoTCi5jv4kAviaF9PypiLmRPFQclWxha5mNZdKHDjvYJ2GNRWU
lZCyk5gl5xh5M+MJGajNt5w0cEEN9vzkvX1RTnMVb0xnW7I1jH5nCMlj/03BsQQp
c5oINwBkGrRlsUWbPkj4y2HIaEsznMHPacOzYmqcDlZF2AhzFJJU+ld0ue8lYGKT
0xps13Zzv/UeqwZNhaT3Y8tO9/ZjTebQ21bwgeDmGoGoRVAUaQQmEHdml5Rr/hMn
PNa6Z8z3EgLbD2GlfTQ4iccW
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