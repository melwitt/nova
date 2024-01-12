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


class EphemeralEncryptionTestBase(base.ServersTestBase):

    def setUp(self):
        # Use a fake key manager service.
        self.flags(
            backend='castellan.tests.unit.key_manager.mock_key_manager.'
                'MockKeyManager', group='key_manager')
        super().setUp()
        self.key_mgr = crypto._get_key_manager()

    def _create_server_with_ephemeral_encryption(self, **kwargs):
        extra_specs = {'hw:ephemeral_encryption': 'true'}
        flavor_id = self._create_flavor(extra_spec=extra_specs)
        server = self._create_server(flavor_id=flavor_id, **kwargs)

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
        server = self._create_server_with_ephemeral_encryption()

        # There should be two secrets in the key manager, one for the root disk
        # and one for the ephemeral disk from the default flavor.
        keymgr_secrets = self._get_key_mgr_secrets(ctx)
        self.assertEqual(2, len(keymgr_secrets))

        # The default flavor has ephemeral=10, so we will have two disks, the
        # root disk and the ephemeral disk.
        bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
            ctx, server['id'])
        self.assertEqual(2, len(bdms))
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


class EphemeralEncryptionTestResize(EphemeralEncryptionTestBase):

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

        # The default flavor has ephemeral=10, so we will have two disks, the
        # root disk and the ephemeral disk.
        bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
            ctx, server['id'])
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


class EphemeralEncryptionTestColdMigrate(EphemeralEncryptionTestBase):

    ADMIN_API = True

    def test_cold_migrate_server(self):
        self.useFixture(fixtures.MockPatch(
            'nova.virt.libvirt.driver.LibvirtDriver._get_instance_disk_info'))
        self.useFixture(fixtures.MockPatch('os.rename'))
        self.useFixture(fixtures.MockPatch(
            'nova.virt.libvirt.driver.LibvirtDriver.'
            'check_instance_shared_storage_remote', return_value=False))
        # This is needed for this test but not for test_create_server. (???)
        self.useFixture(fixtures.MockPatch(
            'nova.virt.libvirt.driver.LibvirtDriver.delete_instance_files'))

        self.start_compute(hostname='compute1')
        self.start_compute(hostname='compute2')
        self._run_periodics()

        ctx = nova_context.get_admin_context()

        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(ctx)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption()
        src_host = self._show_server(server)['OS-EXT-SRV-ATTR:host']

        # There should be two secrets in the key manager, one for the root disk
        # and one for the ephemeral disk from the default flavor.
        keymgr_secrets = self._get_key_mgr_secrets(ctx)
        self.assertEqual(2, len(keymgr_secrets))

        # The default flavor has ephemeral=10, so we will have two disks, the
        # root disk and the ephemeral disk.
        bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
            ctx, server['id'])
        self.assertEqual(2, len(bdms))
        # Verify that libvirt secrets were created for each disk.
        src_driver = self.computes[src_host].driver
        self.assertSecretsMatch(src_driver, bdms, keymgr_secrets)

        # Cold migrate the server.
        self._migrate_server(server)
        dest_host = self._show_server(server)['OS-EXT-SRV-ATTR:host']

        # Assert that it moved.
        self.assertNotEqual(src_host, dest_host)

        # Assert that the libvirt secrets have been removed from the source.
        for bdm in bdms:
            usage_id = f'{bdm.instance_uuid}_{bdm.uuid}'
            s = src_driver._host.find_secret('volume', usage_id)
            self.assertIsNone(s)

        # The libvirt secrets should be on the destination now and we should
        # still have the key manager secrets matching.
        keymgr_secrets_after_migrate = self._get_key_mgr_secrets(ctx)
        dest_driver = self.computes[dest_host].driver
        self.assertSecretsMatch(
            dest_driver, bdms, keymgr_secrets_after_migrate)

        # Revert the migration.
        self._revert_resize(server)

        # Assert that it moved back.
        self.assertEqual(
            src_host, self._show_server(server)['OS-EXT-SRV-ATTR:host'])

        # Assert that the libvirt secrets have been removed from the
        # destination.
        for bdm in bdms:
            usage_id = f'{bdm.instance_uuid}_{bdm.uuid}'
            s = dest_driver._host.find_secret('volume', usage_id)
            self.assertIsNone(s)

        # The libvirt secrets should be on the source now and we should
        # still have the key manager secrets matching.
        keymgr_secrets_after_revert = self._get_key_mgr_secrets(ctx)
        self.assertSecretsMatch(src_driver, bdms, keymgr_secrets_after_revert)

        # Cold migrate the server again.
        self._migrate_server(server)

        # Assert that it moved.
        self.assertEqual(
            dest_host, self._show_server(server)['OS-EXT-SRV-ATTR:host'])

        # Assert that the libvirt secrets have been removed from the source.
        for bdm in bdms:
            usage_id = f'{bdm.instance_uuid}_{bdm.uuid}'
            s = src_driver._host.find_secret('volume', usage_id)
            self.assertIsNone(s)

        # The libvirt secrets should be on the destination now and we should
        # still have the key manager secrets matching.
        keymgr_secrets_after_migrate = self._get_key_mgr_secrets(ctx)
        dest_driver = self.computes[dest_host].driver
        self.assertSecretsMatch(
            dest_driver, bdms, keymgr_secrets_after_migrate)

        # Confirm the migration.
        self._confirm_resize(server)

        # The libvirt secrets should still be not on the source.
        for bdm in bdms:
            usage_id = f'{bdm.instance_uuid}_{bdm.uuid}'
            s = src_driver._host.find_secret('volume', usage_id)
            self.assertIsNone(s)

        # The libvirt secrets should still be on the destination and we should
        # still have the key manager secrets matching.
        keymgr_secrets_after_migrate = self._get_key_mgr_secrets(ctx)
        dest_driver = self.computes[dest_host].driver
        self.assertSecretsMatch(
            dest_driver, bdms, keymgr_secrets_after_migrate)

        # Delete the server.
        self._delete_server(server)

        # Verify that there are no libvirt secrets on either host.
        for bdm in bdms:
            usage_id = f'{bdm.instance_uuid}_{bdm.uuid}'
            s = src_driver._host.find_secret('volume', usage_id)
            self.assertIsNone(s)
            s = dest_driver._host.find_secret('volume', usage_id)
            self.assertIsNone(s)

        # Verify that key manager secrets were deleted for each disk.
        self.assertEqual(0, len(self.key_mgr.list(ctx)))


class EphemeralEncryptionLiveMigrateBase(
    # This has to go before EphemeralEncryptionTestBase so that it patches the
    # LibvirtFixture before useFixture(LibvirtFixture) happens.
    base.LibvirtMigrationMixin,
    EphemeralEncryptionTestBase,
):
    # Some live migration auto-configuration was added in later microversions.
    microversion = 'latest'
    ADMIN_API = True

    def setUp(self):
        super().setUp()
        self.useFixture(fixtures.MockPatch(
            'nova.virt.libvirt.driver.LibvirtDriver._get_instance_disk_info'))
        self.useFixture(fixtures.MockPatch('os.rename'))
        self.useFixture(fixtures.MockPatch(
            'nova.virt.libvirt.driver.LibvirtDriver.'
            'check_instance_shared_storage_remote', return_value=False))
        self.useFixture(fixtures.MockPatch(
            'nova.virt.libvirt.driver.LibvirtDriver.'
            '_check_shared_storage_test_file', return_value=False))
        # This is needed for this test but not for test_create_server. (???)
        self.useFixture(fixtures.MockPatch(
            'nova.virt.libvirt.driver.LibvirtDriver.delete_instance_files'))

        self.start_compute(hostname='compute1')
        self.start_compute(hostname='compute2')
        self._run_periodics()


class EphemeralEncryptionLiveMigrate(EphemeralEncryptionLiveMigrateBase):

    def test_live_migrate_server(self):
        ctx = nova_context.get_admin_context()

        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(ctx)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption(
            networks='none')
        src_host = self._show_server(server)['OS-EXT-SRV-ATTR:host']

        # There should be two secrets in the key manager, one for the root disk
        # and one for the ephemeral disk from the default flavor.
        keymgr_secrets = self._get_key_mgr_secrets(ctx)
        self.assertEqual(2, len(keymgr_secrets))

        # The default flavor has ephemeral=10, so we will have two disks, the
        # root disk and the ephemeral disk.
        bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
            ctx, server['id'])
        self.assertEqual(2, len(bdms))
        # Verify that libvirt secrets were created for each disk.
        src_driver = self.computes[src_host].driver
        self.assertSecretsMatch(src_driver, bdms, keymgr_secrets)

        # Set stuff LibvirtMigrationMixin needs in order to work.
        self.server = server
        self.src = self.computes[src_host]
        self.dest = [v for k, v in self.computes.items() if k != src_host][0]

        # Live migrate the server.
        self._live_migrate_server(server)
        dest_host = self._show_server(server)['OS-EXT-SRV-ATTR:host']

        # Assert that it moved.
        self.assertNotEqual(src_host, dest_host)

        # Assert that the libvirt secrets have been removed from the source.
        for bdm in bdms:
            usage_id = f'{bdm.instance_uuid}_{bdm.uuid}'
            s = src_driver._host.find_secret('volume', usage_id)
            self.assertIsNone(s)

        # The libvirt secrets should be on the destination now and we should
        # still have the key manager secrets matching.
        keymgr_secrets_after_migrate = self._get_key_mgr_secrets(ctx)
        dest_driver = self.computes[dest_host].driver
        self.assertSecretsMatch(
            dest_driver, bdms, keymgr_secrets_after_migrate)

        # Delete the server.
        self._delete_server(server)

        # Verify that there are no libvirt secrets on either host.
        for bdm in bdms:
            usage_id = f'{bdm.instance_uuid}_{bdm.uuid}'
            s = src_driver._host.find_secret('volume', usage_id)
            self.assertIsNone(s)
            s = dest_driver._host.find_secret('volume', usage_id)
            self.assertIsNone(s)

        # Verify that key manager secrets were deleted for each disk.
        self.assertEqual(0, len(self.key_mgr.list(ctx)))


class EphemeralEncryptionLiveMigrateFail(EphemeralEncryptionLiveMigrateBase):

    def _migrate_stub(self, domain, destination, params, flags):
        # Make the live migration fail.
        conn = self.src.driver._host.get_connection()
        dom = conn.lookupByUUIDString(self.server['id'])
        dom.fail_job()
        self.migrate_stub_ran = True

    def test_rollback_live_migration(self):
        ctx = nova_context.get_admin_context()

        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr.list(ctx)))

        # Create a server with ephemeral encryption.
        server = self._create_server_with_ephemeral_encryption(
            networks='none')
        src_host = self._show_server(server)['OS-EXT-SRV-ATTR:host']

        # There should be two secrets in the key manager, one for the root disk
        # and one for the ephemeral disk from the default flavor.
        keymgr_secrets = self._get_key_mgr_secrets(ctx)
        self.assertEqual(2, len(keymgr_secrets))

        # The default flavor has ephemeral=10, so we will have two disks, the
        # root disk and the ephemeral disk.
        bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
            ctx, server['id'])
        self.assertEqual(2, len(bdms))
        # Verify that libvirt secrets were created for each disk.
        src_driver = self.computes[src_host].driver
        self.assertSecretsMatch(src_driver, bdms, keymgr_secrets)

        # Set stuff LibvirtMigrationMixin needs in order to work.
        self.server = server
        self.src = self.computes[src_host]
        self.dest = [v for k, v in self.computes.items() if k != src_host][0]

        # Live migrate the server.
        self._live_migrate_server(server, migration_expected_state='failed')

        # Assert that it didn't move.
        self.assertEqual(
            src_host, self._show_server(server)['OS-EXT-SRV-ATTR:host'])

        # Assert that the libvirt secrets have been removed from the
        # destination.
        dest_driver = self.dest.driver
        for bdm in bdms:
            usage_id = f'{bdm.instance_uuid}_{bdm.uuid}'
            s = dest_driver._host.find_secret('volume', usage_id)
            self.assertIsNone(s)

        # The libvirt secrets should be on the source now and we should
        # still have the key manager secrets matching.
        keymgr_secrets_after_migrate_fail = self._get_key_mgr_secrets(ctx)
        self.assertSecretsMatch(
            src_driver, bdms, keymgr_secrets_after_migrate_fail)

        # Delete the server.
        self._delete_server(server)

        # Verify that there are no libvirt secrets on either host.
        for bdm in bdms:
            usage_id = f'{bdm.instance_uuid}_{bdm.uuid}'
            s = src_driver._host.find_secret('volume', usage_id)
            self.assertIsNone(s)
            s = dest_driver._host.find_secret('volume', usage_id)
            self.assertIsNone(s)

        # Verify that key manager secrets were deleted for each disk.
        self.assertEqual(0, len(self.key_mgr.list(ctx)))
