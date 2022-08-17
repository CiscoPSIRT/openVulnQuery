"""
For latest OpenAPI specification file for this API consult:
 https://github.com/CiscoPSIRT/openVulnAPI/blob/master/swagger/openVulnAPIOAS_3_0_3.yaml

 The OpenVulnQuery client implements all the same endpoints but is currently missing some optional parameters.
"""

MIME_TYPE = 'application/json'


def rest_with_auth_headers(auth_token, user_agent):
    """Construct per session for sending with all GET requests to API."""
    return {
        'Authorization': 'Bearer {}'.format(auth_token),
        'Accept': MIME_TYPE,
        'User-Agent': user_agent,
    }
