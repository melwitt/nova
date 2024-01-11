===================================
Encryption of local ephemeral disks
===================================

.. important::

   The functionality described below is only supported by the libvirt/KVM
   driver.

   This functionality described below is **not** related to LVM ephemeral
   storage encryption. The following config options:

   * :oslo.config:option:`ephemeral_storage_encryption.enabled`
   * :oslo.config:option:`ephemeral_storage_encryption.cipher`
   * :oslo.config:option:`ephemeral_storage_encryption.key_size`

   are **not** used by this feature.

The ephemeral encryption feature in Nova enables a deployment to support
encryption at rest of the local ephemeral disks of servers including: root
disk, ephemeral disk, and swap disk. "Local ephemeral disks" are disks that are
stored and managed by Nova and they follow the life cycle of a server. When a
server is deleted, its local ephemeral disks are also deleted.


Management of secret data with the Key Manager service
------------------------------------------------------

The passphrases of encrypted disks are managed using a Key Manager service such
as Barbican_.

Nova will create, retrieve, and delete disk passphrases using the authorization
token of the user calling Nova API. The cloud operator must consider the
implications of secret ownership with regard to server actions and who is
allowed to perform them::

    ┌─────────────────────┐                        ┌────────────────────┐
    │                     │                        │                    │
    │                     │                        │                    │
    │       Nova API      │◄───────────────────────┤    Barbican API    │
    │                     │                        │                    │
    │                     ├─────┬────────────┬────►│                    │
    │                     │     │ User token │     │                    │
    │                     │     └────────────┘     │                    │
    │                     │                        │                    │
    └──────────▲──────────┘                        └────────────────────┘
               │
               │
               │
               │
               │
  ┌────────────┤
  │ User token │
  └────────────┤
               │
               │
               │
               │
          ┌─────────┐
          │         │
          │  User   │
          │         │
          └─────────┘

By default, Barbican scopes the ownership of a secret at the project level.
This means that many calls in the Barbican API will perform an additional check
to ensure that the ``project_id`` of the token matches the ``project_id``
stored as the secret owner. Users who are members of the same project have
access to each other's secrets in this configuration.

For admin-only APIs such as cold migration, live migration, and evacuate, the
user calling Nova API to perform these server actions needs to be able to
access the Barbican secrets of the owner of the server in addition to having
the ``admin`` role. In a default Barbican configuration, secret ownership will
be scoped to the project which created it, so in such an environment a user
would need to be a `project administrator`_ or any user who has both project
membership and the ``admin`` role.

Note that it is possible for cloud operators to implement more fine-grained
control of secrets in Barbican using `access control lists`_. Secrets could be
made to be scoped at the user level, for example, instead of at the project
level. In such a configuration, a `project administrator`_,  would **not** be
allowed perform admin-only API server actions on a server belonging to a
different user in the project.

Operators must plan ahead to determine what configuration and access control of
Barbican secrets they need in their environments.

.. important::

   For legacy deployments using ``[oslo_policy]enforce_scope = False`` in their
   service configuration files, an additional step is required to allow
   users to create servers with encrypted local disks.

   In a legacy deployment, users must have the ``creator`` role or the
   ``admin`` role assigned to them in Keystone in order to be allowed to
   create secrets in the Barbican key manager service. Otherwise, requests to
   create servers with encrypted local disks will fail.

   .. code-block:: console
      :emphasize-lines: 7

      $ openstack role list
      +----------------------------------+---------------------------+
      | ID                               | Name                      |
      +----------------------------------+---------------------------+
      | 068b4910f0eb4a1cb6a4a2a1e94c3dfe | reader                    |
      | 25dc4ed8f3814fd1941a580d78f2b635 | service                   |
      | 7e832eeb2c2842c9b03c376bf3113247 | creator                   |
      | 59df386beb0f460095b7622fc1a45e22 | member                    |
      | 655bbf1b9f844399bcfbfbbef4248045 | admin                     |
      +----------------------------------+---------------------------+

.. _Barbican: https://docs.openstack.org/barbican/latest/index.html
.. _access control lists: https://docs.openstack.org/barbican/latest/admin/access_control.html
.. _project administrator: https://docs.openstack.org/keystone/latest/admin/service-api-protection.html#project-administrators


Flavor or image requested encryption
------------------------------------

Encryption of local ephemeral disks can be requested through a flavor or an
image.

Encryption requested by flavor
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following flavor extra specs are used to request encryption:

* ``hw:ephemeral_encryption``
* ``hw:ephemeral_encryption_format``

.. code-block:: console

   $ openstack flavor create --disk 1 --ram 256 --vcpus 1 --property hw:ephemeral_encryption=true letsencrypt

   $ openstack flavor show letsencrypt
   +----------------------------+--------------------------------------+
   | Field                      | Value                                |
   +----------------------------+--------------------------------------+
   | OS-FLV-DISABLED:disabled   | False                                |
   | OS-FLV-EXT-DATA:ephemeral  | 0                                    |
   | access_project_ids         | None                                 |
   | description                | None                                 |
   | disk                       | 1                                    |
   | id                         | e76649f1-fafc-4fcb-a4d1-de4f9e4fc709 |
   | name                       | letsencrypt                          |
   | os-flavor-access:is_public | True                                 |
   | properties                 | hw:ephemeral_encryption='true'       |
   | ram                        | 256                                  |
   | rxtx_factor                | 1.0                                  |
   | swap                       | 0                                    |
   | vcpus                      | 1                                    |
   +----------------------------+--------------------------------------+

   $ openstack server create --image myimage --flavor letsencrypt myserver

Encryption requested by image
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following image properties are used to request encryption:

* ``hw_ephemeral_encryption``
* ``hw_ephemeral_encryption_format``

.. code-block:: console

   $ openstack image create --file myimagefile --property hw_ephemeral_encryption=true letsencrypt

   $ openstack image show letsencrypt

   +------------------+-----------------------------------------------------------+
   | Field            | Value                                                     |
   +------------------+-----------------------------------------------------------+
   | checksum         | c8fc807773e5354afe61636071771906                          |
   | container_format | bare                                                      |
   | created_at       | 2024-01-16T04:03:05Z                                      |
   | disk_format      | qcow2                                                     |
   | file             | /v2/images/edafe29a-4c51-4b0d-a3d0-5d073d3c8f69/file      |
   | id               | edafe29a-4c51-4b0d-a3d0-5d073d3c8f69                      |
   | min_disk         | 0                                                         |
   | min_ram          | 0                                                         |
   | name             | letsencrypt                                               |
   | owner            | c6127959b7d244dbb4da9bf7cb86c30d                          |
   | properties       | hw_ephemeral_encryption='true'                            |
   | protected        | False                                                     |
   | schema           | /v2/schemas/image                                         |
   | size             | 21430272                                                  |
   | status           | active                                                    |
   | tags             |                                                           |
   | updated_at       | 2024-01-16T04:03:07Z                                      |
   | virtual_size     | 117440512                                                 |
   | visibility       | public                                                    |
   +------------------+-----------------------------------------------------------+

   $ openstack server create --image letsencrypt --flavor myflavor myserver


Supported server actions
------------------------

The following server actions are supported for servers with local ephemeral
disk encryption:

* create/delete
* start/stop
* reboot soft/hard
* pause/unpause
* suspend/resume
* console create/show
* interface attach/detach
* volume attach/detach
* diagnostics show
* resize
* cold migration
* live migration
* rebuild
* evacuate
* rescue
* snapshot
* shelve/unshelve


Secret handling for server actions
----------------------------------

New passphrases are created whenever a new local disk is created or when a new
image (snapshot) is created.  The only exceptions to this are shelve/unshelve
and rebuilds. Secrets are reused in these two cases to prevent a change in
ownership of the secrets used to encrypt the disks.

This table illustrates how encrypted disk passphrases are handled in various
scenarios.

.. table::
   :align: left

   +--------------------+-------------+--------------------------------------+------------------------------------------------------+
   | Instance or Image  | Disk        | Secret                               | Notes                                                |
   |                    |             | (passphrase)                         |                                                      |
   +====================+=============+======================================+======================================================+
   | Instance A         | disk (root) | Secret 1                             | Secret 1, 2, and 3 will be automatically deleted     |
   |                    +-------------+--------------------------------------+ by Nova when Instance A is deleted and its disks are |
   |                    | disk.eph0   | Secret 2                             | destroyed                                            |
   |                    +-------------+--------------------------------------+                                                      |
   |                    | disk.swap   | Secret 3                             |                                                      |
   +--------------------+-------------+--------------------------------------+------------------------------------------------------+
   | Image Z (snapshot) | disk (root) | Secret 4                             | Secret 4 will **not** be automatically deleted and   |
   | created from       |             |                                      | manual deletion will be needed if/when Image Z is    |
   | Instance A         |             |                                      | deleted from Glance                                  |
   +--------------------+-------------+--------------------------------------+------------------------------------------------------+
   | Instance B         | disk (root) | Secret 5                             | Secret 5, 6, 7, and 8 will be automatically deleted  |
   | created from       |             +--------------------------------------+ by Nova when Instance B is deleted and its disks are |
   | Image Z (snapshot) |             | Secret 6 :sup:`*` (copy of Secret 4) | destroyed                                            |
   |                    +-------------+--------------------------------------+                                                      |
   |                    | disk.eph0   | Secret 7                             |                                                      |
   |                    +-------------+--------------------------------------+                                                      |
   |                    | disk.swap   | Secret 8                             |                                                      |
   +--------------------+-------------+--------------------------------------+------------------------------------------------------+
   | Instance C         | disk (root) | Secret 9                             | Secret 9, 10, and 11 will be automatically deleted   |
   |                    +-------------+--------------------------------------+ by Nova when Instance C is deleted and its disks are |
   |                    | disk.eph0   | Secret 10                            | destroyed                                            |
   |                    +-------------+--------------------------------------+                                                      |
   |                    | disk.swap   | Secret 11                            |                                                      |
   +--------------------+-------------+--------------------------------------+------------------------------------------------------+
   | Image Y (snapshot) | disk (root) | Secret 9                             | Secret 9 is **reused** when Instance C is shelved    |
   | created by shelve  |             |                                      | in part to prevent the possibility of a change in    |
   | of Instance C      |             |                                      | ownership of the root disk secret if, for example,   |
   |                    |             |                                      | an admin user shelves a non-admin user's instance.   |
   |                    |             |                                      | This approach could be avoided if there is some way  |
   |                    |             |                                      | we could create a new secret using the instance's    |
   |                    |             |                                      | user/project rather than the shelver's user/project  |
   +--------------------+-------------+--------------------------------------+------------------------------------------------------+
   | Rescue disk        | disk (root) | Secret 12                            | Secret 12 is stashed in the instance's system        |
   | created by rescue  |             |                                      | metadata with key                                    |
   | of Instance A      |             |                                      | ``rescue_disk_ephemeral_encryption_secret_uuid``.    |
   |                    |             |                                      | This is done because a BDM record for the rescue     |
   |                    |             |                                      | disk is not going to be persisted to the database.   |
   |                    |             |                                      | Secret 12 will be automatically deleted by Nova when |
   |                    |             |                                      | Instance A is unrescued                              |
   +--------------------+-------------+--------------------------------------+------------------------------------------------------+
   | Rescue disk        | disk (root) | Secret 13                            | Secret 13 is stashed in the instance's system        |
   | created by rescue  |             |                                      | metadata with key                                    |
   | of Instance A      |             |                                      | ``rescue_disk_ephemeral_encryption_secret_uuid``.    |
   | using encrypted    |             +--------------------------------------+ This is done because a BDM record for the rescue     |
   | rescue image       |             | Secret 14 :sup:`*`                   | disk is not going to be persisted to the database.   |
   |                    |             | (copy of rescue image secret)        | Secret 13 and 14 will be automatically deleted by    |
   |                    |             |                                      | Nova when Instance A is unrescued                    |
   +--------------------+-------------+--------------------------------------+------------------------------------------------------+

:sup:`*` backing file secret for qcow2 only


Invalid REST API requests for encryption
----------------------------------------

There are some requests for ephemeral encryption that are not allowed by the
REST API.

Conflicts between the flavor and the image
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The API will reject requests where the server flavor ephemeral encryption extra
specs explicitly conflict with the image properties.

Some examples:

.. table::
   :align: left

   +-------------------------------------+-------------------------------------+---------------+
   | Flavor                              | Image                               | Result        |
   +=====================================+=====================================+===============+
   | ``hw:ephemeral_encryption='true'``  | ``hw_ephemeral_encryption='false'`` | ✘             |
   +-------------------------------------+-------------------------------------+---------------+
   | ``hw:ephemeral_encryption='false'`` | ``hw_ephemeral_encryption='true'``  | ✘             |
   +-------------------------------------+-------------------------------------+---------------+
   | ``hw:ephemeral_encryption='true'``  | ``hw_ephemeral_encryption='true'``  | ✓             |
   +-------------------------------------+-------------------------------------+---------------+
   | ``hw:ephemeral_encryption='true'``  |                                     | ✓             |
   +-------------------------------------+-------------------------------------+---------------+
   |                                     | ``hw_ephemeral_encryption='true'``  | ✓             |
   +-------------------------------------+-------------------------------------+---------------+

Resizes from not encrypted to encrypted and vice versa
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Nova is not going to convert existing disks from not encrypted to encrypted and
vice versa, so requests to do that will be rejected by the REST API.

Similarly:

.. table::
   :align: left

   +-------------------------------------+-------------------------------------+---------------+
   | Current flavor                      | New flavor                          | Result        |
   +=====================================+=====================================+===============+
   | ``hw:ephemeral_encryption='true'``  | ``hw:ephemeral_encryption='false'`` | ✘             |
   +-------------------------------------+-------------------------------------+---------------+
   | ``hw:ephemeral_encryption='false'`` | ``hw:ephemeral_encryption='true'``  | ✘             |
   +-------------------------------------+-------------------------------------+---------------+
   | ``hw:ephemeral_encryption='true'``  | ``hw:ephemeral_encryption='true'``  | ✓             |
   +-------------------------------------+-------------------------------------+---------------+
   | ``hw:ephemeral_encryption='true'``  |                                     | ✓             |
   +-------------------------------------+-------------------------------------+---------------+
   |                                     | ``hw:ephemeral_encryption='true'``  | ✓             |
   +-------------------------------------+-------------------------------------+---------------+


Changing a server from not encrypted to encrypted and vice versa
----------------------------------------------------------------

The supported way to change a server from not using encryption to using
encryption is by requesting a rebuild with a new image.

.. code-block:: console

   $ openstack server rebuild --image myimage myserver

.. table::
   :align: left

   +-------------------------------------+-------------------------------------+---------------------------------------+
   | Current image                       | New image                           | Result                                |
   +=====================================+=====================================+=======================================+
   |                                     | ``hw_ephemeral_encryption='true'``  | New local disks will be encrypted     |
   +-------------------------------------+-------------------------------------+---------------------------------------+
   | ``hw_ephemeral_encryption='true'``  |                                     | New local disks will not be encrypted |
   +-------------------------------------+-------------------------------------+---------------------------------------+

.. note::

   The REST API will only accept requests to rebuild a server from not
   encrypted to encrypted from the ``user_id`` that owns the server. This is
   to prevent a change in ownership of the secrets used to encrypt the disks.


Snapshots of servers with ephemeral encryption
----------------------------------------------

When a request to snapshot a server is received, Nova will make a copy of the
image and upload it to the image service, Glance.  Prior to uploading, Nova
will add image properties ``hw_ephemeral_encryption='true'``,
``hw_ephemeral_encryption_format='<format>'``, and
``hw_ephemeral_encryption_secret_uuid='<secret uuid>'`` to the snapshot image.
The ``hw_ephemeral_encryption_secret_uuid`` is the secret required to decrypt
the image.

When a user makes a request to create a server from an encrypted image, Nova
will retrieve the secret indicated by the
``hw_ephemeral_encryption_secret_uuid`` image property and use it to make a
copy of the image for the local disk being created for the new server. This
means that only users who have permissions to access the secret identified by
``hw_ephemeral_encryption_secret_uuid`` will be allowed to create servers using
that snapshot.

.. note::

   The image secret ``hw_ephemeral_encryption_secret_uuid`` will never be
   deleted by Nova as it is coupled with the image residing in Glance. It would
   only be safe to delete the secret from Barbican if and when the image is
   deleted from Glance.  For this reason, Nova will not attempt to delete
   secrets associated with Glance images.

   It is the responsibility of the owner of the Glance image snapshot to delete
   the Barbican secret associated with it, when desired.
