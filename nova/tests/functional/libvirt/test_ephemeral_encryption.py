# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import fixtures
from oslo_log import log as logging

import nova.conf
from nova import context as nova_context
from nova import crypto
from nova import objects
from nova.tests.functional.libvirt import base

CONF = nova.conf.CONF
LOG = logging.getLogger(__name__)


class EphemeralEncryptionServersTest(base.ServersTestBase):

    # many move operations are admin-only
    ADMIN_API = True

    def setUp(self):
        # Use a fake key manager service.
        self.flags(
            backend='castellan.tests.unit.key_manager.mock_key_manager.'
                'MockKeyManager', group='key_manager')
        super().setUp()
        self.key_mgr = crypto._get_key_manager()

    def _create_server_with_ephemeral_encryption(self):
        extra_specs = {'hw:ephemeral_encryption': 'true'}
        flavor_id = self._create_flavor(extra_spec=extra_specs)
        server = self._create_server(flavor_id=flavor_id)

        return server

    def test_create_server(self):
        compute = self.start_compute()
        driver = self.computes[compute].driver
        self._run_periodics()

        # Verify we are reporting the correct traits.
        traits = self._get_provider_traits(self.compute_rp_uuids[compute])
        for trait in ('COMPUTE_EPHEMERAL_ENCRYPTION',
                      'COMPUTE_EPHEMERAL_ENCRYPTION_LUKS'):
            self.assertIn(trait, traits)

        ctx = nova_context.get_admin_context()

        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(ctx)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption()

        # There should be two secrets in the key manager, one for the root disk
        # and one for the ephemeral disk from the default flavor.
        self.assertEqual(2, len(self.key_mgr.list(ctx)))

        bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
            ctx, server['id'])
        # The default flavor has ephemeral=10, so we will have two disks, the
        # root disk and the ephemeral disk.
        self.assertEqual(2, len(bdms))
        # Verify that libvirt secrets were created for each disk.
        for bdm in bdms:
            usage_id = f'{bdm.instance_uuid}_{bdm.uuid}'
            s = driver._host.find_secret('volume', usage_id)
            self.assertIsNotNone(s)

        # Now delete the server.
    def test_resize_server(self):
        self.flags(allow_resize_to_same_host=True)
        self.useFixture(fixtures.MockPatch(
            'nova.virt.libvirt.driver.LibvirtDriver._get_instance_disk_info'))
        self.useFixture(fixtures.MockPatch('os.rename'))
        # This is needed for this test but not for test_create_server. (???)
        self.useFixture(fixtures.MockPatch(
            'nova.virt.libvirt.driver.LibvirtDriver.delete_instance_files'))

        compute = self.start_compute()
        driver = self.computes[compute].driver
        self._run_periodics()

        ctx = nova_context.get_admin_context()

        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(ctx)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption()

        # There should be two secrets in the key manager, one for the root disk
        # and one for the ephemeral disk from the default flavor.
        keymgr_secrets = self._get_key_mgr_secrets(ctx)
        self.assertEqual(2, len(keymgr_secrets))

        bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
            ctx, server['id'])
        # The default flavor has ephemeral=10, so we will have two disks, the
        # root disk and the ephemeral disk.
        self.assertEqual(2, len(bdms))
        # Verify that libvirt secrets were created for each disk.
        self.assertSecretsMatch(driver, bdms, keymgr_secrets)

        # Make note of the original flavor and create a new flavor.
        server_details = self._show_server(server)
        orig_flavor_id = server_details['flavor']['id']
        extra_specs = {'hw:ephemeral_encryption': 'true'}
        new_flavor_id = self._create_flavor(extra_spec=extra_specs)

        # Resize the server to the new flavor.
        self._resize_server(server, new_flavor_id)

        # Assert the server now has the new flavor.
        server_details = self._show_server(server)
        self.assertEqual(new_flavor_id, server_details['flavor']['id'])

        # We should still have two key manager secrets and two libvirt secrets
        # and they should be the same ones from earlier.
        keymgr_secrets_after_resize = self._get_key_mgr_secrets(ctx)
        self.assertEqual(keymgr_secrets, keymgr_secrets_after_resize)
        self.assertSecretsMatch(driver, bdms, keymgr_secrets_after_resize)

        # Revert the resize.
        self._revert_resize(server)

        # Assert the server is back to the original flavor.
        server_details = self._show_server(server)
        self.assertEqual(orig_flavor_id, server_details['flavor']['id'])

        # Resize the server again.
        self._resize_server(server, new_flavor_id)

        # Assert the server now has the new flavor.
        server_details = self._show_server(server)
        self.assertEqual(new_flavor_id, server_details['flavor']['id'])

        # Confirm the resize.
        self._confirm_resize(server)

        # Assert the server still has the new flavor.
        server_details = self._show_server(server)
        self.assertEqual(new_flavor_id, server_details['flavor']['id'])

        # We should still have two key manager secrets and two libvirt secrets
        # and they should be the same ones from earlier.
        keymgr_secrets_after_resize = self._get_key_mgr_secrets(ctx)
        self.assertEqual(keymgr_secrets, keymgr_secrets_after_resize)
        self.assertSecretsMatch(driver, bdms, keymgr_secrets_after_resize)

        # Delete the server.
        self._delete_server(server)

        # Verify that libvirt secrets were deleted for each disk.
        for bdm in bdms:
            usage_id = f'{bdm.instance_uuid}_{bdm.uuid}'
            s = driver._host.find_secret('volume', usage_id)
            self.assertIsNone(s)

        # Verify that key manager secrets were deleted for each disk.
        self.assertEqual(0, len(self.key_mgr.list(ctx)))
