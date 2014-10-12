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
Module for reading and writing JAR signatures

References
----------
* http://docs.oracle.com/javase/1.5.0/docs/guide/jar/index.html
* http://java.sun.com/j2se/1.5.0/docs/guide/jar/jar.html#JAR%20Manifest

:author: Christopher O'Brien  <obriencj@gmail.com>
:license: LGPL
"""


import os

from .manifest import Manifest, NAMED_DIGESTS

from base64 import b64encode


__all__ = (
    "SignatureManfiest",
)


class SignatureManifest(Manifest):
    """
    Represents a KEY.SF signature file.  Structure is similar to that
    of Manifest. Each section represents a crypto checksum of a matching
    section from a MANIFEST.MF
    """

    primary_key = "Signature-Version"


    def digest_manifest(self, manifest, java_algorithm="SHA-256"):
        """
        Create a main section checksum and sub-section checksums based off
        of the data from an existing manifest using an algorithm given
        by Java-style name.
        """

        # pick a line separator for creating checksums of the manifest
        # contents. We want to use either the one from the given
        # manifest, or the OS default if it hasn't specified one.
        linesep = manifest.linesep or os.linesep

        all_key = java_algorithm + "-Digest-Manifest"
        main_key = java_algorithm + "-Digest-Manifest-Main-Attributes"
        sect_key = java_algorithm + "-Digest"

        # determine a digest class to use based on the java-style
        # algorithm name
        digest = _get_digest(java_algorithm)

        # calculate the checksum for the main manifest section. We'll
        # be re-using this digest to also calculate the total
        # checksum.
        h_all = digest()
        h_all.update(manifest.get_main_section())
        self[main_key] = b64encode(h_all.digest())

        for sub_section in manifest.sub_sections.values():
            sub_data = sub_section.get_data(linesep)

            # create the checksum of the section body and store it as a
            # sub-section of our own
            h_section = digest()
            h_section.update(sub_data)
            sf_sect = self.create_section(sub_section.primary())
            sf_sect[sect_key] = b64encode(h_section.digest())

            # push this data into this total as well.
            h_all.update(sub_data)

        # after traversing all the sub sections, we now have the
        # digest of the whole manifest.
        self[all_key] = b64encode(h_all.digest())


    def verify_manifest_checksums(self, manifest):
        """
        Verifies the checksums over the given manifest.
        :return: error message, or None if verification succeeds
        Reference:
        http://docs.oracle.com/javase/7/docs/technotes/guides/jar/jar.html#Signature_Validation
        """

        # NOTE: JAR spec does not state whether there can be >1 digest
        # used, and should the validator require any or all digests to
        # match.  We allow mismatching digests and require just one to
        # be correct.  We see no security risk: it is the signer of
        # the .SF file who shall check, what is being signed.

        # TODO: no. If there are digests, check them all. Any failing
        # digest should result in failure.

        for java_digest in self.keys_with_suffix("-Digest-Manifest"):
            whole_mf_digest = b64_encoded_digest(
                manifest.get_data(),
                NAMED_DIGESTS[java_digest]
            )

            # It is enough for at least one digest to be correct
            if whole_mf_digest == self.get(java_digest + "-Digest-Manifest"):
                return None

        # JAR spec allows for the checksum of the whole manifest to
        # mismatch.  There is a second chance for the verification to
        # succeed: checksum for the main section matches, plus
        # checksum for every subsection matches.

        at_least_one_main_attr_digest_matches = False
        for java_digest in self.keys_with_suffix(
                "-Digest-Manifest-Main-Attributes"):
            mf_main_attr_digest = b64_encoded_digest(
                manifest.get_main_section(),
                NAMED_DIGESTS[java_digest]
            )

            if mf_main_attr_digest == self.get(
                    java_digest + "-Digest-Manifest-Main-Attributes"):
                at_least_one_main_attr_digest_matches = True
                break

        if not at_least_one_main_attr_digest_matches:
            return "No matching checksum of the whole manifest and no " \
                   "matching checksum of the manifest main attributes found"

        for s in manifest.sub_sections.values():
            at_least_one_section_digest_matches = False
            sf_section = self.create_section(s.primary(), overwrite=False)
            for java_digest in s.keys_with_suffix("-Digest"):
                section_digest = b64_encoded_digest(
                    s.get_data(manifest.linesep),
                    NAMED_DIGESTS[java_digest]
                )
                if section_digest == sf_section.get(java_digest + "-Digest"):
                    at_least_one_section_digest_matches = True
                    break

            if not at_least_one_section_digest_matches:
                return "No matching checksum of the whole manifest and " \
                       "no matching checksum for subsection %s found" \
                           % s.primary()
        return None


    def get_signature(self, certificate, private_key):
        """
        Produces a signature block for the contents of this signature
        manifest. Executes the `openssl` binary in order to calculate
        this. TODO: replace this with a pyopenssl call

        References
        ----------
        http://docs.oracle.com/javase/7/docs/technotes/guides/jar/jar.html#Digital_Signatures

        Parameters
        ----------
        certificate : `str` filename
          certificate to embed into the signature (PEM format)
        private_key : `str` filename
          RSA private key used to sign (PEM format)

        Returns
        -------
        signature : `str`
          content of the signature block file as though produced by
          jarsigner.

        Raises
        ------
        cpe : `CalledProcessError`
          if there was a non-zero return code from running the
          underlying openssl exec
        """

        # There seems to be no Python crypto library, which would
        # produce a JAR-compatible signature. So this is a wrapper
        # around external command.  OpenSSL is known to work.

        # Any other command which reads data on stdin and returns
        # JAR-compatible "signature file block" on stdout can be used.
        # Note: Oracle does not specify the content of the "signature
        # file block", friendly saying that "These are binary files
        # not intended to be interpreted by humans"

        from subprocess import Popen, PIPE, CalledProcessError

        # TODO: handle also DSA and ECDSA keys
        external_cmd = "openssl cms -sign -binary -noattr -md SHA256" \
                       " -signer %s -inkey %s -outform der" \
                       % (certificate, private_key)

        proc = Popen(external_cmd.split(),
                     stdin=PIPE, stdout=PIPE, stderr=PIPE)

        (proc_stdout, proc_stderr) = proc.communicate(input=self.get_data())

        if proc.returncode != 0:
            print proc_stderr
            raise CalledProcessError(proc.returncode, external_cmd, sys.stderr)
        else:
            return proc_stdout


    def verify(self, manifest):
        """
        Verifies that the checksums for the individual sections of this
        signature manifest match the values of the related manifest sections
        from within the given manifest instance
        """

        pass


def b64_encoded_digest(data, algorithm):
    h = algorithm()
    h.update(data)
    return b64encode(h.digest())


def verify_signature_block(certificate_file, content_file, signature):
    """
    A wrapper over 'OpenSSL cms -verify'.
    Verifies the 'signature_stream' over the 'content' with the 'certificate'.
    :return: Error message, or None if the signature validates.
    """

    # TODO: move to using pyopenssl

    from subprocess import Popen, PIPE, STDOUT

    external_cmd = "openssl cms -verify -CAfile %s -content %s " \
                   "-inform der" % (certificate_file, content_file)

    proc = Popen(external_cmd.split(),
                 stdin=PIPE, stdout=PIPE, stderr=STDOUT)

    proc_output = proc.communicate(input=signature)[0]

    if proc.returncode != 0:
        return "Command \"%s\" returned %s: %s" \
               % (external_cmd, proc.returncode, proc_output)

    return None


def verify(certificate, jarinfo, key_alias):
    """
    Verifies signature of a JAR file.

    Limitations:
    - only RSA keys are handled
    - diagnostic is less verbose than of jarsigner
    :return: tuple (exit_status, result_message)

    Reference:
    http://docs.oracle.com/javase/7/docs/technotes/guides/jar/jar.html#Signature_Validation
    Note that the validation is done in three steps. Failure at any step is a failure
    of the whole validation.
    """

    from tempfile import mkstemp

    zip_file = jarinfo.get_zipfile()
    sf_data = zip_file.read("META-INF/%s.SF" % key_alias)

    # Step 1: check the crypto part.
    sf_file = mkstemp()[1]
    with open(sf_file, "w") as tmp_buf:
        tmp_buf.write(sf_data)
        tmp_buf.flush()
        sig_block_data = zip_file.read("META-INF/%s.RSA" % key_alias)
        error = verify_signature_block(certificate, sf_file, sig_block_data)
        os.unlink(sf_file)
        if error is not None:
            return error

    # KEYALIAS.SF is correctly signed.
    # Step 2: Check that it contains correct checksum of the manifest.
    signature_manifest = SignatureManifest()
    signature_manifest.parse(sf_data)

    jar_manifest = Manifest()
    jar_manifest.parse(zip_file.read("META-INF/MANIFEST.MF"))

    error = signature_manifest.verify_manifest_checksums(jar_manifest)
    if error is not None:
        return error

    # Checksums of MANIFEST.MF itself are correct.
    # Step 3: Check that it contains valid checksums for each file from the JAR.
    error = jar_manifest.verify_jar_checksums(jar_file)
    if error is not None:
        return error

    return None


#
# The end.
