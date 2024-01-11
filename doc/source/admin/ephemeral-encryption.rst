===============================
Encrypted local ephemeral disks
===============================

.. important::

   The functionality described below is only supported by the libvirt/KVM
   driver.

   This functionality described below  is **not** related to LVM ephemeral
   storage encryption. The config options
   :oslo.config:option:`ephemeral_storage_encryption.enabled`,
   :oslo.config:option:`ephemeral_storage_encryption.cipher`, and
   :oslo.config:option:`ephemeral_storage_encryption.key_size` are **not** used
   by this feature.

The ephemeral encryption feature in Nova enables a deployment to support
encryption of instances local ephemeral disks: root disk, ephemeral disk, and
swap disk. "Local ephemeral disks" are disks that are stored and managed by
Nova and they follow the lifecycle of an instance. When an instance is deleted,
its local ephemeral disks are also deleted.

