IPS_SIGNATURE_LABEL = 'ips_signatures'
PLATFORMS_LABEL = 'platforms'

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
    PLATFORMS_LABEL,
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

PLATFORMS = (
    'id',
    'name',
    'firstFixes',
    'vulnerabilityState',
)

ALLOWS_FILTER = (
    'all',
    'severity',
)

ALLOWS_OPTIONAL = (
    'platformAlias',
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

SUPPORTED_PLATFORMS_ALIAS_NAME_ASA = (
    'ISA3000',
    'ASAV',
    'ASA5500X',
    'ASASM',
    'FPR1000',
    'FPR2100',
    'FPR4100',
    'FPR9000',
    'FWL3100',
)

SUPPORTED_PLATFORMS_ALIAS_NAME_FTD = (
    'ISA3000',
    'ASA5500',
    'FPR1000',
    'FPR2100',
    'FPR4100',
    'FPR9000',
    'FPRNGFW',
    'FWL3100',
)

SUPPORTED_PLATFORMS_ALIAS_NAME_FXOS = (
    'FPR4100',
    'FPR9000',
)

SUPPORTED_PLATFORMS_ALIAS_NAME_NXOS = (
    'MDS9000',
    'NEXUS1000V',
    'NEXUS3000',
    'NEXUS5000',
    'NEXUS6000',
    'NEXUS7000',
    'NEXUS9000',
)

NA_INDICATOR = 'NA'

JSON_OUTPUT_FORMAT_TOKEN = 'json'
CSV_OUTPUT_FORMAT_TOKEN = 'csv'

DEFAULT_ADVISORY_FORMAT_TOKEN = 'default'
IOS_ADVISORY_FORMAT_TOKEN = 'ios'
IOSXE_ADVISORY_FORMAT_TOKEN = 'ios_xe'

ADVISORY_FORMAT_TOKENS = (
    DEFAULT_ADVISORY_FORMAT_TOKEN,
    IOS_ADVISORY_FORMAT_TOKEN,
)
