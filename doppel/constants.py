"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

DOPPEL_TOKEN_URL = 'https://api.doppel.com/oauth/token'
DOPPEL_AUDIENCE = 'doppel-external'
DOPPEL_GRANT_TYPE = 'client_credentials'

AUTH_TYPE_API_KEY = 'API Key'
AUTH_TYPE_OAUTH = 'OAuth'

API_VERSION_V1 = 'v1/'
API_VERSION_V2 = 'v2/'

ALERT_STATE = {
    "Doppel Review": "doppel_review",
    "Needs Confirmation": "needs_confirmation",
    "Actioned": "actioned",
    "Taken Down": "taken_down",
    "Monitoring": "monitoring",
    "Archived": "archived"
}

PRODUCT = {
    "Domains": "domains",
    "Social Media": "social_media",
    "Mobile Apps": "mobile_apps",
    "Ecommerce": "ecommerce",
    "Crypto": "crypto",
    "Email": "email",
    "Paid Ads": "paid_ads",
    "Telco": "telco"
}

SORT_BY = {
    "Date Sourced": "date_sourced",
    "Date Last Actioned": "date_last_actioned"
}

SORT_ORDER = {
    "Ascending": "asc",
    "Descending": "desc"
}
