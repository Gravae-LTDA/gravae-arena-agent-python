import unittest
from unittest.mock import patch
from direct_installer import monitor_inventory, InstallError

class InventoryTest(unittest.TestCase):
    def test_inventory_contains_only_observed_slugs_without_credentials(self):
        data = {'monitors': [{'monitorId': 'quadra01_camera01', 'blockSlug': 'quadra01', 'cameraSlug': 'camera01', 'rtspUrl': 'secret'}]}
        with patch('direct_installer.camera_sources', return_value={'quadra01_camera01': {'rtspUrl': 'rtsp://user:password@camera'}}) as read:
            self.assertEqual(monitor_inventory(data), [{'monitorId': 'quadra01_camera01', 'blockSlug': 'quadra01', 'cameraSlug': 'camera01'}])
            read.assert_called_once_with(data)
    def test_does_not_publish_config_as_inventory_when_shinobi_read_fails(self):
        with patch('direct_installer.camera_sources', side_effect=InstallError('CAMERA_MAPPING_REQUIRED')):
            with self.assertRaises(InstallError): monitor_inventory({'monitors': []})
