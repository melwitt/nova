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

from oslo_log import log as logging

import nova.conf
from nova import context as nova_context
from nova import crypto
from nova import objects
from nova.tests.functional.libvirt import base

CONF = nova.conf.CONF
LOG = logging.getLogger(__name__)


class EphemeralEncryptionTestBase(base.ServersTestBase):

    def setUp(self):
        # Use a fake key manager service.
        self.flags(
            backend='castellan.tests.unit.key_manager.mock_key_manager.'
                'MockKeyManager', group='key_manager')
        super().setUp()
        self.key_mgr = crypto._get_key_manager()

    def _create_server_with_ephemeral_encryption_flavor(self):
        extra_specs = {'hw:ephemeral_encryption': 'true'}
        flavor_id = self._create_flavor(
            disk=10, ephemeral=5, swap=128, extra_spec=extra_specs)
        server = self._create_server(flavor_id=flavor_id)
        return server

    def _get_key_mgr_secrets(self, ctx):
        # Return a dict of {uuid: secret}
        return {obj.id: obj.value for obj in self.key_mgr.list(ctx)}

    def assertSecretsMatch(self, driver, bdms, keymgr_secrets):
        for bdm in bdms:
            self.assertIn(bdm.encryption_secret_uuid, keymgr_secrets.keys())
            usage_id = f'{bdm.instance_uuid}_{bdm.uuid}'
            s = driver._host.find_secret('volume', usage_id)
            self.assertIn(s.value(), keymgr_secrets.values())


class EphemeralEncryptionTestCreate(EphemeralEncryptionTestBase):

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
        server = self._create_server_with_ephemeral_encryption_flavor()

        # There should be three secrets in the key manager, one for the root
        # disk, one for the ephemeral disk, and one for the swap disk.
        keymgr_secrets = self._get_key_mgr_secrets(ctx)
        self.assertEqual(3, len(keymgr_secrets))

        # The flavor we created has ephemeral=5 and swap=128, so we will have
        # three disks, the root disk, an ephemeral disk, and a swap disk.
        bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
            ctx, server['id'])
        self.assertEqual(3, len(bdms))
        # Verify that libvirt secrets were created for each disk.
        self.assertSecretsMatch(driver, bdms, keymgr_secrets)

        # Now delete the server.
        self._delete_server(server)

        # Verify that libvirt secrets were deleted for each disk.
        for bdm in bdms:
            usage_id = f'{bdm.instance_uuid}_{bdm.uuid}'
            s = driver._host.find_secret('volume', usage_id)
            self.assertIsNone(s)

        # Verify that key manager secrets were deleted for each disk.
        self.assertEqual(0, len(self.key_mgr.list(ctx)))
