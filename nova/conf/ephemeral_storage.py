# Copyright 2015 Huawei Technology corp.
# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_config import cfg

ephemeral_storage_encryption_group = cfg.OptGroup(
    name='ephemeral_storage_encryption',
    title='Ephemeral storage encryption options')

ephemeral_storage_encryption_opts = [
    cfg.BoolOpt('enabled',
        default=False,
        deprecated_for_removal=True,
        deprecated_since='29.0.0',
        deprecated_reason="""
Support for flavor and image based ephemeral storage encryption was added in
the 29.0.0 Caracal release and the legacy implementation using ``dm-crypt``
will be removed in a future release.

Limited support for ``dm-crypt`` will be introduced using the new framework
before the legacy implementation is removed.
""",
        help="""
Enables/disables LVM ephemeral storage encryption.
"""),
    cfg.StrOpt('cipher',
        default='aes-xts-plain64',
        deprecated_for_removal=True,
        deprecated_since='29.0.0',
        deprecated_reason="""
Support for flavor and image based ephemeral storage encryption was added in
the 29.0.0 Caracal release and the legacy implementation using ``dm-crypt``
will be removed in a future release.

Limited support for ``dm-crypt`` will be introduced using the new framework
before the legacy implementation is removed.
""",
        help="""
Cipher-mode string to be used.

The cipher and mode to be used to encrypt ephemeral storage. The set of
cipher-mode combinations available depends on kernel support. According
to the ``dm-crypt`` documentation, the cipher is expected to be in the format:
"<cipher>-<chainmode>-<ivmode>".

Possible values:

* Any crypto option listed in ``/proc/crypto``.
"""),
    cfg.IntOpt('key_size',
        default=512,
        min=1,
        deprecated_for_removal=True,
        deprecated_since='29.0.0',
        deprecated_reason="""
Support for flavor and image based ephemeral storage encryption was added in
the 29.0.0 Caracal release and the legacy implementation using ``dm-crypt``
will be removed in a future release.

Limited support for ``dm-crypt`` will be introduced using the new framework
before the legacy implementation is removed.
""",
        help="""
Encryption key length in bits.

The bit length of the encryption key to be used to encrypt ephemeral storage.
In XTS mode only half of the bits are used for encryption key.
"""),
    cfg.StrOpt(
        'default_format',
        default='luks',
        choices=('luks',),
        help="""
Default ephemeral encryption format.

Only 'luks' is supported at this time.

Note that this does not apply to LVM ephemeral storage encryption.
"""),
]


def register_opts(conf):
    conf.register_group(ephemeral_storage_encryption_group)
    conf.register_opts(ephemeral_storage_encryption_opts,
                       group=ephemeral_storage_encryption_group)


def list_opts():
    return {ephemeral_storage_encryption_group:
            ephemeral_storage_encryption_opts}
