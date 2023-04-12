import unittest
from openVulnQuery import advisory
from openVulnQuery import constants

NA = constants.NA_INDICATOR
IPS_SIG = constants.IPS_SIGNATURE_LABEL
mock_advisory_title = "Mock Advisory Title"
adv_cfg = {
    'advisory_id': "Cisco-SA-20111107-CVE-2011-0941",
    'sir': "Medium",
    'first_published': "2023-04-05T21:36:55+0000",
    'last_updated': "2023-04-05T21:36:55+0000",
    'cves': ["CVE-2023-20102", NA],
    'bug_ids': "CSCwc95889",
    'cvss_base_score': "7.0",
    'advisory_title': "{}".format(mock_advisory_title),
    'publication_url': "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-stealthsmc-rce-sfNBPjcS",
    'cwe': NA,
    'cvrfUrl': "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-stealthsmc-rce-sfNBPjcS/cvrf/cisco-sa-stealthsmc-rce-sfNBPjcS_cvrf.xml",
    'csafUrl': "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-stealthsmc-rce-sfNBPjcS/csaf/cisco-sa-stealthsmc-rce-sfNBPjcS.json",
    'product_names': ["product_name_1", "product_name_2"],
    'summary': "This is summary",
    IPS_SIG: [],
    'platforms': []
}
mock_advisory = advisory.AdvisoryDefault(**adv_cfg)
mock_advisories = [mock_advisory]


class MockLogger(object):
    def debug(self, *args, **kwargs):
        pass


class AdvisoryTest(unittest.TestCase):
    def test_advisory_filterable_succeeds(self):
        self.assertTrue(advisory.Filterable())

    def test_advisory_advisorydefault_succeeds(self):
        """
        Test the advisory_factory function for the default format.
        """
        adv_map = {}
        for k, v in advisory.ADVISORIES_COMMONS_MAP.items():
            adv_map[k] = NA
        adv_map[IPS_SIG] = []
        adv_map['platforms'] = []
        self.assertTrue(advisory.AdvisoryDefault(**adv_map))

    def test_advisory_advisoryios_succeeds(self):
        """
        Test the advisory_factory function for the IOS format.
        """
        adv_map = {}
        for k, v in advisory.ADVISORIES_COMMONS_MAP.items():
            adv_map[k] = NA
        adv_map.update({
            'first_fixed': '',
            'ios_release': '',
            'IPS_SIG': [],
            'platforms': []
        })
        self.assertTrue(advisory.AdvisoryIOS(**adv_map))

    def test_advisory_advisory_factory_default_succeeds(self):
        
        adv_map = {}
        for k, v in advisory.ADVISORIES_COMMONS_MAP.items():
            adv_map[v] = k
        adv_map.update({
            advisory.IPS_SIG_MAP[advisory.IPS_SIG]: [],
            'platforms': []
        })
        self.assertTrue(advisory.advisory_factory(
            adv_map,
            constants.DEFAULT_ADVISORY_FORMAT_TOKEN,
            MockLogger()))

    def test_advisory_advisory_factory_ios_succeeds(self):
        
        adv_map = {}
        for k, v in advisory.ADVISORIES_COMMONS_MAP.items():
            adv_map[v] = k
        adv_map.update({
            advisory.IPS_SIG_MAP[advisory.IPS_SIG]: [],
            'platforms': [],
            'first_fixed': '',
            'ios_release': '',
        })
        self.assertTrue(advisory.advisory_factory(
            adv_map,
            constants.IOS_ADVISORY_FORMAT_TOKEN,
            MockLogger()))

    def test_advisory_advisory_format_factory_map_succeeds(self):
        """
        Test the advisory_format_factory_map function to verify it returns the correct mapping.
        """
        factory_map = advisory.advisory_format_factory_map()
        self.assertEqual(factory_map[constants.DEFAULT_ADVISORY_FORMAT_TOKEN], advisory.AdvisoryDefault)
        self.assertEqual(factory_map[constants.IOS_ADVISORY_FORMAT_TOKEN], advisory.AdvisoryIOS)

    def test_advisory_platformslist_succeeds(self):
        """
        Test the platformsList class to verify it's created correctly with provided arguments.
        """
        platforms_data = {
            'id': NA,
            'name': NA,
            'firstFixes': [],
            'vulnerabilityState': NA
        }
        self.assertTrue(advisory.platformsList(**platforms_data))


if __name__ == '__main__':
    unittest.main()
