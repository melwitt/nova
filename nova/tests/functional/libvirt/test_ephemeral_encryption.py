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

from unittest import mock

from castellan.common.objects import passphrase
from castellan.key_manager import key_manager
import fixtures
from oslo_log import log as logging
from oslo_utils import uuidutils

import nova.conf
from nova import context as nova_context
from nova import crypto
from nova import exception
from nova import objects
from nova.tests.functional.api import client
from nova.tests.functional.libvirt import base

CONF = nova.conf.CONF
LOG = logging.getLogger(__name__)


class FakeKeyManager(key_manager.KeyManager):
    """A fake key manager.

    This key manager implementation supports a minimum subset of methods
    specified by the key manager interface that are required for vTPM. Side
    effects (e.g., raising exceptions) for each method are handled as specified
    by the key manager interface.
    """

    def __init__(self, configuration):
        super().__init__(configuration)

        #: A mapping of UUIDs to passphrases.
        self._passphrases = {}

    def create_key(self, context, algorithm, length, **kwargs):
        """Creates a symmetric key.

        This is not implemented as it's unnecessary here.
        """
        raise NotImplementedError(
            "FakeKeyManager does not support symmetric keys"
        )

    def create_key_pair(self, context, **kwargs):
        """Creates an asymmetric keypair.

        This is not implemented as it's unnecessary here.
        """
        raise NotImplementedError(
            "FakeKeyManager does not support asymmetric keys"
        )

    def store(self, context, managed_object, **kwargs):
        """Stores (i.e., registers) a passphrase with the key manager."""
        if context is None:
            raise exception.Forbidden()

        if not isinstance(managed_object, passphrase.Passphrase):
            raise exception.KeyManagerError(
                reason='cannot store anything except passphrases')

        uuid = uuidutils.generate_uuid()
        managed_object._id = uuid  # set the id to simulate persistence
        self._passphrases[uuid] = managed_object

        return uuid

    def get(self, context, managed_object_id):
        """Retrieves the key identified by the specified id.

        This implementation returns the key that is associated with the
        specified UUID. A Forbidden exception is raised if the specified
        context is None; a KeyError is raised if the UUID is invalid.
        """
        if context is None:
            raise exception.Forbidden()

        if managed_object_id not in self._passphrases:
            raise KeyError('cannot retrieve non-existent secret')

        return self._passphrases[managed_object_id]

    def delete(self, context, managed_object_id):
        """Represents deleting the key.

        Simply delete the key from our list of keys.
        """
        if context is None:
            raise exception.Forbidden()

        if managed_object_id not in self._passphrases:
            raise exception.KeyManagerError(
                reason="cannot delete non-existent secret")

        del self._passphrases[managed_object_id]


class EphemeralEncryptionServersTest(base.ServersTestBase):

    # many move operations are admin-only
    ADMIN_API = True

    def setUp(self):
        # Use a fake key manager service.
        self.flags(
            backend='nova.tests.functional.libvirt.'
                    'test_ephemeral_encryption.FakeKeyManager',
            group='key_manager')
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
        driver.capabilities['supports_ephemeral_encryption'] = True
        driver.capabilities['supports_ephemeral_encryption_luks'] = True
        self._run_periodics()

        # ensure we are reporting the correct traits
        traits = self._get_provider_traits(self.compute_rp_uuids[compute])
        for trait in ('COMPUTE_EPHEMERAL_ENCRYPTION',
                      'COMPUTE_EPHEMERAL_ENCRYPTION_LUKS'):
            self.assertIn(trait, traits)

        # Verify there are no secrets in the key manager.
        self.assertEqual(0, len(self.key_mgr._passphrases))

        # create a server with ephemeral encryption
        server = self._create_server_with_ephemeral_encryption()

        # There should be two secrets in the key manager, one for the root disk
        # and one for the ephemeral disk from the default flavor.
        self.assertEqual(2, len(self.key_mgr._passphrases))

        ctx = nova_context.get_admin_context()
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

        # now delete the server
        self._delete_server(server)

        # Verify that libvirt secrets were deleted for each disk.
        for bdm in bdms:
            usage_id = f'{bdm.instance_uuid}_{bdm.uuid}'
            s = driver._host.find_secret('volume', usage_id)
            self.assertIsNone(s)

        # ensure we deleted the key now that we no longer need it
        self.assertEqual(0, len(self.key_mgr._passphrases))

#    def test_suspend_resume_server(self):
#        self.start_compute()
#
#        # create a server with vTPM
#        server = self._create_server_with_vtpm()
#        self.addCleanup(self._delete_server, server)
#
#        # suspend the server
#        server = self._suspend_server(server)
#
#        # ensure our instance's system_metadata field and key manager inventory
#        # is correct
#        self.assertInstanceHasSecret(server)
#
#        # resume the server
#        server = self._resume_server(server)
#
#        # ensure our instance's system_metadata field and key manager inventory
#        # is still correct
#        self.assertInstanceHasSecret(server)
#
#    def test_soft_reboot_server(self):
#        self.start_compute()
#
#        # create a server with vTPM
#        server = self._create_server_with_vtpm()
#
#        # soft reboot the server
#        server = self._reboot_server(server, hard=False)
#        self.addCleanup(self._delete_server, server)
#
#        # ensure our instance's system_metadata field and key manager inventory
#        # is still correct
#        self.assertInstanceHasSecret(server)
#
#    def test_hard_reboot_server(self):
#        self.start_compute()
#
#        # create a server with vTPM
#        server = self._create_server_with_vtpm()
#        self.addCleanup(self._delete_server, server)
#
#        # hard reboot the server
#        server = self._reboot_server(server, hard=True)
#
#        # ensure our instance's system_metadata field and key manager inventory
#        # is still correct
#        self.assertInstanceHasSecret(server)
#
#    def test_resize_server__no_vtpm_to_vtpm(self):
#        for host in ('test_compute0', 'test_compute1'):
#            self.start_compute(host)
#
#        # create a server without vTPM
#        server = self._create_server_without_vtpm()
#        self.addCleanup(self._delete_server, server)
#
#        # ensure our instance's system_metadata field and key manager inventory
#        # is correct
#        self.assertInstanceHasNoSecret(server)
#
#        # create a flavor with vTPM
#        extra_specs = {'hw:tpm_model': 'tpm-tis', 'hw:tpm_version': '1.2'}
#        flavor_id = self._create_flavor(extra_spec=extra_specs)
#
#        # TODO(stephenfin): The mock of 'migrate_disk_and_power_off' should
#        # probably be less...dumb
#        with mock.patch(
#            'nova.virt.libvirt.driver.LibvirtDriver'
#            '.migrate_disk_and_power_off', return_value='{}',
#        ):
#            # resize the server to a new flavor *with* vTPM
#            server = self._resize_server(server, flavor_id=flavor_id)
#
#        # ensure our instance's system_metadata field and key manager inventory
#        # is updated to reflect the new vTPM requirement
#        self.assertInstanceHasSecret(server)
#
#        # revert the instance rather than confirming it, and ensure the secret
#        # is correctly cleaned up
#
#        # TODO(stephenfin): The mock of 'migrate_disk_and_power_off' should
#        # probably be less...dumb
#        with mock.patch(
#            'nova.virt.libvirt.driver.LibvirtDriver'
#            '.migrate_disk_and_power_off', return_value='{}',
#        ):
#            # revert back to the old flavor *without* vTPM
#            server = self._revert_resize(server)
#
#        # ensure we delete the new key since we no longer need it
#        self.assertInstanceHasNoSecret(server)
#
#    def test_resize_server__vtpm_to_no_vtpm(self):
#        for host in ('test_compute0', 'test_compute1'):
#            self.start_compute(host)
#
#        # create a server with vTPM
#        server = self._create_server_with_vtpm()
#        self.addCleanup(self._delete_server, server)
#
#        # ensure our instance's system_metadata field is correct
#        self.assertInstanceHasSecret(server)
#
#        # create a flavor without vTPM
#        flavor_id = self._create_flavor()
#
#        # TODO(stephenfin): The mock of 'migrate_disk_and_power_off' should
#        # probably be less...dumb
#        with mock.patch(
#            'nova.virt.libvirt.driver.LibvirtDriver'
#            '.migrate_disk_and_power_off', return_value='{}',
#        ):
#            # resize the server to a new flavor *without* vTPM
#            server = self._resize_server(server, flavor_id=flavor_id)
#
#        # ensure we still have the key for the vTPM device in storage in case
#        # we revert
#        self.assertInstanceHasSecret(server)
#
#        # confirm the instance and ensure the secret is correctly cleaned up
#
#        # TODO(stephenfin): The mock of 'migrate_disk_and_power_off' should
#        # probably be less...dumb
#        with mock.patch(
#            'nova.virt.libvirt.driver.LibvirtDriver'
#            '.migrate_disk_and_power_off', return_value='{}',
#        ):
#            # revert back to the old flavor *with* vTPM
#            server = self._confirm_resize(server)
#
#        # ensure we have finally deleted the key for the vTPM device since
#        # there is no going back now
#        self.assertInstanceHasNoSecret(server)
#
#    def test_migrate_server(self):
#        for host in ('test_compute0', 'test_compute1'):
#            self.start_compute(host)
#
#        # create a server with vTPM
#        server = self._create_server_with_vtpm()
#        self.addCleanup(self._delete_server, server)
#
#        # ensure our instance's system_metadata field is correct
#        self.assertInstanceHasSecret(server)
#
#        # TODO(stephenfin): The mock of 'migrate_disk_and_power_off' should
#        # probably be less...dumb
#        with mock.patch(
#            'nova.virt.libvirt.driver.LibvirtDriver'
#            '.migrate_disk_and_power_off', return_value='{}',
#        ):
#            # cold migrate the server
#            self._migrate_server(server)
#
#        # ensure nothing has changed
#        self.assertInstanceHasSecret(server)
#
#    def test_live_migrate_server(self):
#        for host in ('test_compute0', 'test_compute1'):
#            self.start_compute(host)
#
#        # create a server with vTPM
#        server = self._create_server_with_vtpm()
#        self.addCleanup(self._delete_server, server)
#
#        # ensure our instance's system_metadata field is correct
#        self.assertInstanceHasSecret(server)
#
#        # live migrate the server
#        self.assertRaises(
#            client.OpenStackApiException,
#            self._live_migrate_server, server)
#
#    def test_shelve_server(self):
#        for host in ('test_compute0', 'test_compute1'):
#            self.start_compute(host)
#
#        # create a server with vTPM
#        server = self._create_server_with_vtpm()
#        self.addCleanup(self._delete_server, server)
#
#        # ensure our instance's system_metadata field is correct
#        self.assertInstanceHasSecret(server)
#
#        # attempt to shelve the server
#        self.assertRaises(
#            client.OpenStackApiException,
#            self._shelve_server, server)
