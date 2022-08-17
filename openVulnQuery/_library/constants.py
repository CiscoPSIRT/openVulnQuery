IPS_SIGNATURE_LABEL = 'ips_signatures'

API_LABELS = (
    'advisory_id',
    'advisory_title',
    'bug_ids',
    'cves',
    'cvrfUrl',
    'csafUrl',
    'cvss_base_score',
    'cwe',
    'first_fixed',
    'first_published',
    'ios_release',
    IPS_SIGNATURE_LABEL,
    'last_updated',
    'product_names',
    'publication_url',
    'sir',
    'summary',
)

IPS_SIGNATURES = (
    'legacy_ips_id',
    'legacy_ips_url',
    'release_version',
    'software_version',
)

ALLOWS_FILTER = (
    'all',
    'severity',
)

NON_ADVISORY_QUERY = (
    'OS',
    'platform',
)

SUPPORTED_PLATFORMS_VERSION = (
    'aci',
    'asa',
    'ios',
    'iosxe',
    'ftd',
    'fmc',
    'fxos',
    'nxos',
)

SUPPORTED_PLATFORMS_ALIAS = (
    'asa',
    'ftd',
    'fxos',
    'nxos',
)

NA_INDICATOR = 'NA'

JSON_OUTPUT_FORMAT_TOKEN = 'json'
CSV_OUTPUT_FORMAT_TOKEN = 'csv'


DEFAULT_ADVISORY_FORMAT_TOKEN = 'default'
IOS_ADVISORY_FORMAT_TOKEN = 'ios'

ADVISORY_FORMAT_TOKENS = (
    DEFAULT_ADVISORY_FORMAT_TOKEN,
    IOS_ADVISORY_FORMAT_TOKEN,
)
