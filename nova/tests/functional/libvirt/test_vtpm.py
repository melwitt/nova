# Copyright (C) 2020 Red Hat, Inc.
# All Rights Reserved.
#
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
import ddt
from oslo_log import log as logging
from oslo_utils import uuidutils

import nova.conf
from nova import context as nova_context
from nova import crypto
from nova import exception
from nova import objects
from nova.tests.functional.api import client
from nova.tests.functional.libvirt import base
from nova import utils

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

    def add_consumer(self, context, managed_object_id, consumer_data):
        raise NotImplementedError(
            'FakeKeyManager does not implement adding consumers'
        )

    def remove_consumer(self, context, managed_object_id, consumer_data):
        raise NotImplementedError(
            'FakeKeyManager does not implement removing consumers'
        )


@ddt.ddt
class VTPMServersTest(base.LibvirtMigrationMixin, base.ServersTestBase):

    # many move operations are admin-only
    ADMIN_API = True
    # Enables passing host when creating a server
    microversion = '2.74'
    # Reflect reality more for async API requests like live migration
    CAST_AS_CALL = False

    def setUp(self):
        super().setUp()

        # enable vTPM and use our own fake key service
        self.flags(swtpm_enabled=True, group='libvirt')
        self.flags(
            backend='nova.tests.functional.libvirt.test_vtpm.FakeKeyManager',
            group='key_manager')

        # mock the '_check_vtpm_support' function which validates things like
        # the presence of users on the host, none of which makes sense here
        _p = mock.patch(
            'nova.virt.libvirt.driver.LibvirtDriver._check_vtpm_support')
        _p.start()
        self.addCleanup(_p.stop)

        self.key_mgr = crypto._get_key_manager()

    def _create_server_with_vtpm(self, secret_security=None, host=None,
                                 expected_state='ACTIVE'):
        extra_specs = {'hw:tpm_model': 'tpm-tis', 'hw:tpm_version': '1.2'}
        if secret_security:
            extra_specs.update({'hw:tpm_secret_security': secret_security})
        flavor_id = self._create_flavor(extra_spec=extra_specs)
        server = self._create_server(flavor_id=flavor_id, host=host,
                                     expected_state=expected_state,
                                     networks='none')

        return server

    def _create_legacy_server_with_vtpm(self, host):
        with mock.patch.object(host.manager, '_set_tpm_secret_security'):
            server = self._create_server_with_vtpm()
        ctx = nova_context.get_admin_context()
        instance = objects.Instance.get_by_uuid(ctx, server['id'])
        self.assertNotIn('image_hw_tpm_secret_security',
                         instance.system_metadata)
        self.assertNotIn('tpm_secret_security_confirmed',
                         instance.system_metadata)
        return server

    def _create_server_without_vtpm(self):
        # use the default flavor (i.e. one without vTPM extra specs)
        return self._create_server(networks='none')

    def assertInstanceHasSecret(self, server, secret_security=None,
                                confirmed=None):
        ctx = nova_context.get_admin_context()
        instance = objects.Instance.get_by_uuid(ctx, server['id'])
        self.assertIn('vtpm_secret_uuid', instance.system_metadata)
        if secret_security is not None:
            self.assertEqual(
                secret_security,
                instance.system_metadata.get('image_hw_tpm_secret_security'))
        if confirmed is not None:
            self.assertEqual(
                confirmed,
                instance.system_metadata.get('tpm_secret_security_confirmed'))
        self.assertEqual(1, len(self.key_mgr._passphrases))
        self.assertIn(
            instance.system_metadata['vtpm_secret_uuid'],
            self.key_mgr._passphrases)
        return instance.system_metadata['vtpm_secret_uuid']

    def assertInstanceHasNoSecret(self, server):
        ctx = nova_context.get_admin_context()
        instance = objects.Instance.get_by_uuid(ctx, server['id'])
        self.assertNotIn('vtpm_secret_uuid', instance.system_metadata)
        self.assertEqual(0, len(self.key_mgr._passphrases))

    def _assert_libvirt_has_secret(self, host, instance_uuid):
        s = host.driver._host.find_secret('vtpm', instance_uuid)
        self.assertIsNotNone(s)
        ctx = nova_context.get_admin_context()
        instance = objects.Instance.get_by_uuid(ctx, instance_uuid)
        secret_uuid = instance.system_metadata['vtpm_secret_uuid']
        self.assertEqual(secret_uuid, s.UUIDString())

    def _assert_libvirt_had_secret(self, compute, secret_uuid):
        # This assert is for ephemeral private libvirt secrets that we
        # undefine immediately after guest creation. Examples include 'user'
        # and 'deployment' TPM secret security modes and legacy servers.
        # The LibvirtFixture tracks secrets that existed before they were
        # removed, so we can assert this.
        conn = compute.driver._host.get_connection()
        self.assertIn(secret_uuid, conn._removed_secrets)

    def _assert_libvirt_secret_missing(self, host, instance_uuid):
        s = host.driver._host.find_secret('vtpm', instance_uuid)
        self.assertIsNone(s)

    def _assert_legacy_server_migrated_secret_security(
            self, server, secret_security='host'):
        ctx = nova_context.get_admin_context()
        instance = objects.Instance.get_by_uuid(ctx, server['id'])
        self.assertEqual(
            secret_security,
            instance.system_metadata['image_hw_tpm_secret_security'])
        self.assertEqual(
            'False',
            instance.system_metadata['tpm_secret_security_confirmed'])

    def test_tpm_secret_security_user(self):
        self.flags(supported_tpm_secret_security=['user'], group='libvirt')
        host = self.start_compute(hostname='tpm-host')
        compute = self.computes['tpm-host']

        # ensure we are reporting the correct traits
        traits = self._get_provider_traits(self.compute_rp_uuids[host])
        self.assertIn('COMPUTE_SECURITY_TPM_SECRET_SECURITY_USER', traits)

        server = self._create_server_with_vtpm(secret_security='user')

        # The server should have a secret in the key manager service.
        secret_uuid = self.assertInstanceHasSecret(server)

        # And it should have had a libvirt secret created and undefined.
        self._assert_libvirt_had_secret(compute, secret_uuid)

    def test_tpm_secret_security_user_negative(self):
        self.flags(supported_tpm_secret_security=['deployment'],
                   group='libvirt')
        self.start_compute(hostname='tpm-host')
        self._create_server_with_vtpm(secret_security='user',
                                      expected_state='ERROR')

    def test_tpm_secret_security_legacy_instance(self):
        self.flags(default_tpm_secret_security='host', group='libvirt')
        self.start_compute(hostname='tpm-host')

        # Mock out _set_tpm_secret_security() to fake a legacy instance that
        # we'll then migrate by restarting nova-compute.
        compute = self.computes['tpm-host']
        server = self._create_legacy_server_with_vtpm(compute)

        # Now restart nova-compute without the mock, testing that we migrate
        # the instance correctly.
        self.restart_compute_service(hostname='tpm-host')

        self._assert_legacy_server_migrated_secret_security(server)

        # Now restart nova-compute again with a different secret security
        # policy and verify that it did not change the security policy of the
        # instance.
        self.flags(default_tpm_secret_security='user', group='libvirt')
        self.restart_compute_service(hostname='tpm-host')

        self._assert_legacy_server_migrated_secret_security(server)

    def test_create_server(self):
        compute = self.start_compute()

        # ensure we are reporting the correct traits
        traits = self._get_provider_traits(self.compute_rp_uuids[compute])
        for trait in ('COMPUTE_SECURITY_TPM_1_2', 'COMPUTE_SECURITY_TPM_2_0'):
            self.assertIn(trait, traits)

        # create a server with vTPM
        server = self._create_server_with_vtpm()

        # ensure our instance's system_metadata field and key manager inventory
        # is correct
        self.assertInstanceHasSecret(server)

        # now delete the server
        self._delete_server(server)

        # ensure we deleted the key now that we no longer need it
        self.assertEqual(0, len(self.key_mgr._passphrases))

    def test_create_server_secret_security_host(self):
        self.flags(supported_tpm_secret_security=['host'], group='libvirt')
        compute = self.start_compute()

        # ensure we are reporting the correct traits
        traits = self._get_provider_traits(self.compute_rp_uuids[compute])
        self.assertIn('COMPUTE_SECURITY_TPM_SECRET_SECURITY_HOST', traits)

        # create a server with vTPM
        server = self._create_server_with_vtpm(secret_security='host')

        # ensure our instance's system_metadata field and key manager inventory
        # is correct
        self.assertInstanceHasSecret(server, secret_security='host',
                                     confirmed='True')

        # ensure the libvirt secret is defined correctly
        ctx = nova_context.get_admin_context()
        instance = objects.Instance.get_by_uuid(ctx, server['id'])
        conn = self.computes[compute].driver._host.get_connection()
        secret = conn._secrets[instance.system_metadata['vtpm_secret_uuid']]
        self.assertFalse(secret._ephemeral)
        self.assertFalse(secret._private)

        # now delete the server
        self._delete_server(server)

        # ensure we deleted the key and undefined the secret now that we no
        # longer need it
        self.assertEqual(0, len(self.key_mgr._passphrases))
        self.assertNotIn(conn._secrets,
                         instance.system_metadata['vtpm_secret_uuid'])

    def test_create_server_secret_security_deployment(self):
        self.flags(
            supported_tpm_secret_security=['deployment'], group='libvirt')
        self.start_compute(hostname='tpm-host')
        compute = self.computes['tpm-host']

        # ensure we are reporting the correct traits
        traits = self._get_provider_traits(self.compute_rp_uuids['tpm-host'])
        self.assertIn(
            'COMPUTE_SECURITY_TPM_SECRET_SECURITY_DEPLOYMENT', traits)

        # create a server with vTPM
        server = self._create_server_with_vtpm(secret_security='deployment')

        # ensure our instance's system_metadata field and key manager inventory
        # is correct
        self.assertInstanceHasSecret(server, secret_security='deployment',
                                     confirmed='True')

        # ensure the libvirt secret is defined correctly
        ctx = nova_context.get_admin_context()
        instance = objects.Instance.get_by_uuid(ctx, server['id'])
        self._assert_libvirt_had_secret(
            compute, instance.system_metadata['vtpm_secret_uuid'])

        # now delete the server
        self._delete_server(server)

        # ensure we deleted the key and undefined the secret now that we no
        # longer need it
        self.assertEqual(0, len(self.key_mgr._passphrases))
        conn = compute.driver._host.get_connection()
        self.assertNotIn(conn._secrets,
                         instance.system_metadata['vtpm_secret_uuid'])

    @ddt.data('host', 'deployment')
    def test_create_legacy_server_secret_security_host_deployment(
            self, secret_security):
        """Test behavior of guest creation when secret security is unconfirmed

        When a legacy instance has been migrated but has not yet been
        confirmed, it will have a secret security policy recorded in its system
        metadata but we should not act on that policy until the policy has been
        confirmed. Secret security should behave as legacy if unconfirmed.
        """
        self.flags(
            default_tpm_secret_security=secret_security, group='libvirt')
        self.start_compute(hostname='tpm-host')

        # Mock out _set_tpm_secret_security() to fake a legacy instance that
        # we'll then migrate by restarting nova-compute.
        compute = self.computes['tpm-host']
        server = self._create_legacy_server_with_vtpm(compute)

        # Now restart nova-compute without the mock, testing that we migrate
        # the instance correctly.
        self.restart_compute_service(hostname='tpm-host')

        self._assert_legacy_server_migrated_secret_security(
            server, secret_security=secret_security)

        self.assertInstanceHasSecret(
            server, secret_security=secret_security, confirmed='False')

        # The server should not have a libvirt secret because it should have
        # been undefined after guest creation.
        ctx = nova_context.get_admin_context()
        instance = objects.Instance.get_by_uuid(ctx, server['id'])
        conn = compute.driver._host.get_connection()
        secret = conn._removed_secrets[
            instance.system_metadata['vtpm_secret_uuid']]
        self.assertTrue(secret._ephemeral)
        self.assertTrue(secret._private)

        # Suspend and resume the server to force guest creation.
        self._suspend_server(server)
        self._resume_server(server)

        # The server should still not have a libvirt secret i.e. the 'host' or
        # 'deployment' secret security policy should not have been acted upon
        # because it is not yet confirmed.
        instance = objects.Instance.get_by_uuid(ctx, server['id'])
        secret = conn._removed_secrets[
            instance.system_metadata['vtpm_secret_uuid']]
        self.assertTrue(secret._ephemeral)
        self.assertTrue(secret._private)

    def test_live_migrate_legacy_server_secret_security_host_rejected(self):
        """Test the behavior of the API when a legacy server is unconfirmed

        A legacy server that has had a default secret security policy set in
        its system metadata but is still unconfirmed by the user should not be
        allowed to live migrate.
        """
        self.flags(default_tpm_secret_security='host', group='libvirt')
        self.start_compute(hostname='tpm-host')

        # Mock out _set_tpm_secret_security() to fake a legacy instance that
        # we'll then migrate by restarting nova-compute.
        compute = self.computes['tpm-host']
        server = self._create_legacy_server_with_vtpm(compute)

        # Now restart nova-compute without the mock, testing that we migrate
        # the instance correctly.
        self.restart_compute_service(hostname='tpm-host')

        self._assert_legacy_server_migrated_secret_security(server)

        ex = self.assertRaises(
            client.OpenStackApiException, self._live_migrate, server)
        self.assertEqual(400, ex.response.status_code)
        self.assertIn(
            "Operation 'live-migration' not supported for vTPM-enabled "
            "instance", str(ex))

    def test_live_migrate_server_secret_security_host_to_old(self):
        """Test behavior when a new server tries to migrate to an old compute

        We will simulate this by starting one compute without any
        supported_tpm_secret_security to represent an old compute node and try
        to live migrate to it.

        The attempt should fail with NoValidHost.
        """
        self.flags(supported_tpm_secret_security=['host'], group='libvirt')
        self.start_compute(hostname='src')
        self.flags(supported_tpm_secret_security=[], group='libvirt')
        self.start_compute(hostname='dest')

        server = self._create_server_with_vtpm(secret_security='host',
                                               host='src')

        self._live_migrate(server, migration_expected_state='error')

        # Live migration attempt should have failed with NoValidHost because
        # no other host is advertising the
        # COMPUTE_SECURITY_TPM_SECRET_SECURITY_HOST trait.
        event = self._wait_for_instance_action_event(
            server, 'live-migration', 'conductor_live_migrate_instance',
            'Error')
        self.assertIn('NoValidHost', event['traceback'])

    def test_live_migrate_host_server_secret_security_host_to_old(self):
        """Test behavior when a new server tries to migrate to an old compute

        This will request a destination host for live migration.

        We will simulate this by starting one compute without any
        supported_tpm_secret_security to represent an old compute node and try
        to live migrate to it.

        The attempt should fail with NoValidHost.
        """
        self.flags(supported_tpm_secret_security=['host'], group='libvirt')
        self.start_compute(hostname='src')
        self.flags(supported_tpm_secret_security=[], group='libvirt')
        self.start_compute(hostname='dest')

        server = self._create_server_with_vtpm(secret_security='host',
                                               host='src')

        self._live_migrate(
            server, migration_expected_state='error', host='dest')

        # Live migration attempt should have failed with NoValidHost because
        # no other host is advertising the
        # COMPUTE_SECURITY_TPM_SECRET_SECURITY_HOST trait.
        event = self._wait_for_instance_action_event(
            server, 'live-migration', 'conductor_live_migrate_instance',
            'Error')
        self.assertIn('NoValidHost', event['traceback'])

    def test_live_migrate_host_force_server_secret_security_host_to_old(self):
        """Test behavior when a new server tries to migrate to an old compute

        This will request a destination host for live migration and force=True
        by using an older microversion 2.30.

        We will simulate this by starting one compute without any
        supported_tpm_secret_security to represent an old compute node and try
        to live migrate to it.

        This will go through because it bypasses the scheduler entirely.
        """
        self.flags(supported_tpm_secret_security=['host'], group='libvirt')
        self.start_compute(hostname='src')
        self.flags(supported_tpm_secret_security=[], group='libvirt')
        self.start_compute(hostname='dest')
        self.src = self.computes['src']
        self.dest = self.computes['dest']

        self.server = self._create_server_with_vtpm(secret_security='host',
                                                    host='src')

        # FIXME(melwitt): Is this reason enough to do a service version bump
        # and disallow all vTPM live migration until the minimum service
        # version in the deployment is new enough? Or some subset of live
        # migration until the minimum service version is met?
        with utils.temporary_mutation(self.api, microversion='2.30'):
            self.api.post_server_action(
                self.server['id'],
                {'os-migrateLive': {'host': 'dest',
                                    'block_migration': 'auto',
                                    'force': 'True'}})
            self._wait_for_migration_status(self.server, ['accepted'])
            self._wait_for_state_change(self.server, 'ACTIVE')

    def test_live_migrate_server_secret_security_host(self):
        """Test a successful live migration of a server with 'host' security

        Because we have two computes that support the 'host' secret security
        policy, we expect the live migration to be successful.
        """
        self.flags(supported_tpm_secret_security=['host'], group='libvirt')
        self.start_compute(hostname='src')
        self.start_compute(hostname='dest')
        self.src = self.computes['src']
        self.dest = self.computes['dest']

        self.server = self._create_server_with_vtpm(secret_security='host',
                                                    host='src')
        # We should have a secret in the key manager service.
        self.assertInstanceHasSecret(self.server)
        # We should also have a libvirt secret on the source host.
        self._assert_libvirt_has_secret(self.src, self.server['id'])
        # And no libvirt secret on the destination host.
        self._assert_libvirt_secret_missing(self.dest, self.server['id'])

        self._live_migrate(self.server)

        # After the live migration, we should still have a secret in the key
        # manager service.
        self.assertInstanceHasSecret(self.server)
        # We should have removed the libvirt secret from the source host.
        self._assert_libvirt_secret_missing(self.src, self.server['id'])
        # And we should have a libvirt secret on the destination host.
        self._assert_libvirt_has_secret(self.dest, self.server['id'])

    def test_live_migrate_server_secret_security_host_rollback(self):
        """Test a failed live migration of a server with 'host' security

        Simulate a failure and verify that secrets are correctly handled during
        the rollback process.
        """

        def _migrate_stub(domain, destination, params, flags):
            self.dest.driver._host.get_connection().createXML(
                params['destination_xml'],
                'fake-createXML-doesnt-care-about-flags')
            conn = self.src.driver._host.get_connection()
            dom = conn.lookupByUUIDString(self.server['id'])
            dom.fail_job()

        self.flags(supported_tpm_secret_security=['host'], group='libvirt')
        self.start_compute(hostname='src')
        self.start_compute(hostname='dest')
        self.src = self.computes['src']
        self.dest = self.computes['dest']

        self.server = self._create_server_with_vtpm(secret_security='host',
                                                    host='src')
        # We should have a secret in the key manager service.
        self.assertInstanceHasSecret(self.server)
        # We should also have a libvirt secret on the source host.
        self._assert_libvirt_has_secret(self.src, self.server['id'])
        # And no libvirt secret on the destination host.
        self._assert_libvirt_secret_missing(self.dest, self.server['id'])

        with mock.patch('nova.tests.fixtures.libvirt.Domain.migrateToURI3',
                        _migrate_stub):
            self._live_migrate(self.server, migration_expected_state='failed')

        # After the live migration fails, we should still have a secret in the
        # key manager service.
        self.assertInstanceHasSecret(self.server)
        # We should have a libvirt secret on the source host.
        self._assert_libvirt_has_secret(self.src, self.server['id'])
        # And no libvirt secret on the destination host.
        self._assert_libvirt_secret_missing(self.dest, self.server['id'])

    def test_suspend_resume_server(self):
        self.start_compute()

        # create a server with vTPM
        server = self._create_server_with_vtpm()
        self.addCleanup(self._delete_server, server)

        # suspend the server
        server = self._suspend_server(server)

        # ensure our instance's system_metadata field and key manager inventory
        # is correct
        self.assertInstanceHasSecret(server)

        # resume the server
        server = self._resume_server(server)

        # ensure our instance's system_metadata field and key manager inventory
        # is still correct
        self.assertInstanceHasSecret(server)

    def test_soft_reboot_server(self):
        self.start_compute()

        # create a server with vTPM
        server = self._create_server_with_vtpm()

        # soft reboot the server
        server = self._reboot_server(server, hard=False)
        self.addCleanup(self._delete_server, server)

        # ensure our instance's system_metadata field and key manager inventory
        # is still correct
        self.assertInstanceHasSecret(server)

    def test_hard_reboot_server(self):
        self.start_compute()

        # create a server with vTPM
        server = self._create_server_with_vtpm()
        self.addCleanup(self._delete_server, server)

        # hard reboot the server
        server = self._reboot_server(server, hard=True)

        # ensure our instance's system_metadata field and key manager inventory
        # is still correct
        self.assertInstanceHasSecret(server)

    def test_resize_server__no_vtpm_to_vtpm(self):
        for host in ('test_compute0', 'test_compute1'):
            self.start_compute(host)

        # create a server without vTPM
        server = self._create_server_without_vtpm()
        self.addCleanup(self._delete_server, server)

        # ensure our instance's system_metadata field and key manager inventory
        # is correct
        self.assertInstanceHasNoSecret(server)

        # create a flavor with vTPM
        extra_specs = {'hw:tpm_model': 'tpm-tis', 'hw:tpm_version': '1.2'}
        flavor_id = self._create_flavor(extra_spec=extra_specs)

        # TODO(stephenfin): The mock of 'migrate_disk_and_power_off' should
        # probably be less...dumb
        with mock.patch(
            'nova.virt.libvirt.driver.LibvirtDriver'
            '.migrate_disk_and_power_off', return_value='{}',
        ):
            # resize the server to a new flavor *with* vTPM
            server = self._resize_server(server, flavor_id=flavor_id)

        # ensure our instance's system_metadata field and key manager inventory
        # is updated to reflect the new vTPM requirement
        self.assertInstanceHasSecret(server)

        # revert the instance rather than confirming it, and ensure the secret
        # is correctly cleaned up

        # TODO(stephenfin): The mock of 'migrate_disk_and_power_off' should
        # probably be less...dumb
        with mock.patch(
            'nova.virt.libvirt.driver.LibvirtDriver'
            '.migrate_disk_and_power_off', return_value='{}',
        ):
            # revert back to the old flavor *without* vTPM
            server = self._revert_resize(server)

        # ensure we delete the new key since we no longer need it
        self.assertInstanceHasNoSecret(server)

    def test_resize_server__vtpm_to_no_vtpm(self):
        for host in ('test_compute0', 'test_compute1'):
            self.start_compute(host)

        # create a server with vTPM
        server = self._create_server_with_vtpm()
        self.addCleanup(self._delete_server, server)

        # ensure our instance's system_metadata field is correct
        self.assertInstanceHasSecret(server)

        # create a flavor without vTPM
        flavor_id = self._create_flavor()

        # TODO(stephenfin): The mock of 'migrate_disk_and_power_off' should
        # probably be less...dumb
        with mock.patch(
            'nova.virt.libvirt.driver.LibvirtDriver'
            '.migrate_disk_and_power_off', return_value='{}',
        ):
            # resize the server to a new flavor *without* vTPM
            server = self._resize_server(server, flavor_id=flavor_id)

        # ensure we still have the key for the vTPM device in storage in case
        # we revert
        self.assertInstanceHasSecret(server)

        # confirm the instance and ensure the secret is correctly cleaned up

        # TODO(stephenfin): The mock of 'migrate_disk_and_power_off' should
        # probably be less...dumb
        with mock.patch(
            'nova.virt.libvirt.driver.LibvirtDriver'
            '.migrate_disk_and_power_off', return_value='{}',
        ):
            # revert back to the old flavor *with* vTPM
            server = self._confirm_resize(server)

        # ensure we have finally deleted the key for the vTPM device since
        # there is no going back now
        self.assertInstanceHasNoSecret(server)

    def test_migrate_server(self):
        for host in ('test_compute0', 'test_compute1'):
            self.start_compute(host)

        # create a server with vTPM
        server = self._create_server_with_vtpm()
        self.addCleanup(self._delete_server, server)

        # ensure our instance's system_metadata field is correct
        self.assertInstanceHasSecret(server)

        # TODO(stephenfin): The mock of 'migrate_disk_and_power_off' should
        # probably be less...dumb
        with mock.patch(
            'nova.virt.libvirt.driver.LibvirtDriver'
            '.migrate_disk_and_power_off', return_value='{}',
        ):
            # cold migrate the server
            self._migrate_server(server)

        # ensure nothing has changed
        self.assertInstanceHasSecret(server)

    def test_live_migrate_server(self):
        for host in ('test_compute0', 'test_compute1'):
            self.start_compute(host)

        # create a server with vTPM
        server = self._create_server_with_vtpm()
        self.addCleanup(self._delete_server, server)

        # ensure our instance's system_metadata field is correct
        self.assertInstanceHasSecret(server)

        # live migrate the server
        self.assertRaises(
            client.OpenStackApiException,
            self._live_migrate_server, server)

    def test_shelve_server(self):
        for host in ('test_compute0', 'test_compute1'):
            self.start_compute(host)

        # create a server with vTPM
        server = self._create_server_with_vtpm()
        self.addCleanup(self._delete_server, server)

        # ensure our instance's system_metadata field is correct
        self.assertInstanceHasSecret(server)

        # attempt to shelve the server
        self.assertRaises(
            client.OpenStackApiException,
            self._shelve_server, server)
