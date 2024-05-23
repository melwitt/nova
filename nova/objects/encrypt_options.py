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

from nova.objects import base
from nova.objects import fields


@base.NovaObjectRegistry.register
class EncryptOptions(base.NovaEphemeralObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    # Options and defaults were taken from:
    #     https://github.com/qemu/qemu/blob/master/qapi/crypto.json
    fields = {
        # The cipher algorithm for data encryption
        'cipher_algorithm': fields.CipherAlgorithmField(),
        # The cipher mode for data encryption
        'cipher_mode': fields.CipherModeField(),
        # Master key hash algorithm
        'hash_algorithm': fields.HashAlgorithmField(),
        # Number of milliseconds to spend in PBKDF passphrase processing
        'iter_time': fields.IntegerField(),
        # The initialization vector generator
        'ivgen_algorithm': fields.IVGenAlgorithmField(),
        # The initialization vector generator hash
        'ivgen_hash_algorithm': fields.HashAlgorithmField(),
    }

    @classmethod
    def get_default(cls):
        # Supported luks options:
        #
        #  cipher-alg=<str>       - Name of cipher algorithm and key length
        #  cipher-mode=<str>      - Name of encryption cipher mode
        #  hash-alg=<str>         - Name of hash algorithm to use for PBKDF
        #  iter-time=<num>        - Time to spend in PBKDF in milliseconds
        #  ivgen-alg=<str>        - Name of IV generator algorithm
        #  ivgen-hash-alg=<str>   - Name of IV generator hash algorithm
        #
        # NOTE(melwitt): Sensible defaults (that match the qemu
        # defaults) are hardcoded at this time for simplicity and
        # consistency when instances are migrated. Configuration of
        # luks options could be added in a future release.
        obj = cls()
        obj.cipher_algorithm = fields.CipherAlgorithm.AES_256
        obj.cipher_mode = fields.CipherMode.XTS
        obj.hash_algorithm = fields.HashAlgorithm.SHA256
        obj.iter_time = 2000
        obj.ivgen_algorithm = fields.IVGenAlgorithm.PLAIN64
        obj.ivgen_hash_algorithm = fields.HashAlgorithm.SHA256
        return obj
