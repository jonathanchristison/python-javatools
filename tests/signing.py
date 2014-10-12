# This library is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, see
# <http://www.gnu.org/licenses/>.


"""
unit tests for manifest-related functionality of python-javatools

author: Christopher O'Brien  <obriencj@gmail.com>
license: LGPL v.3
"""


from . import get_data_fn
from javatools.jarinfo import JarInfo
from javatools.signing import SignatureManifest, verify
from unittest import TestCase


class SignatureTest(TestCase):


    def verify_signature(self, signed_jar):
        certificate = get_data_fn("javatools-cert.pem")
        jar_data = JarInfo(get_data_fn(signed_jar))
        error_message = verify(certificate, jar_data, "UNUSED")

        self.assertIsNone(error_message,
                          "\"%s\" verification against \"%s\" failed: %s"
                          % (jar_data, certificate, error_message))


    def test_verify_signature_by_javatools(self):
        self.verify_signature("manifest-signed.jar")


    def test_verify_signature_by_jarsigner(self):
        self.verify_signature("manifest-signed-by-jarsigner.jar")


    def test_cli_sign_and_verify(self):

        src = get_data_fn("manifest-sample3.jar")
        key_alias = "SAMPLE3"
        cert = get_data_fn("javatools-cert.pem")
        key = get_data_fn("javatools.pem")
        tmp_jar = mkstemp()[1]
        copyfile(src, tmp_jar)
        cmd = ["manifest", "-s", cert, key, key_alias, tmp_jar]
        self.assertEqual(main(cmd), 0, "Command %s returned non-zero status"
                         % " ".join(cmd))

        certificate = get_data_fn("javatools-cert.pem")
        error_message = verify(certificate, tmp_jar, key_alias)
        self.assertIsNone(error_message,
                          "Verification of JAR which we just signed failed: %s"
                          % error_message)

        unlink(tmp_jar)


#
# The end.
