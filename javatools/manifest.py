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
Module for reading and writing files, related to JAR manifest.

References
----------
* http://docs.oracle.com/javase/1.5.0/docs/guide/jar/index.html
* http://java.sun.com/j2se/1.5.0/docs/guide/jar/jar.html#JAR%20Manifest

:author: Christopher O'Brien  <obriencj@gmail.com>
:license: LGPL
"""


import os
import sys

from base64 import b64encode
from collections import OrderedDict
from cStringIO import StringIO
from itertools import izip
from os.path import isdir, join, sep, split, walk
from zipfile import ZipFile

from . import _BUFFERING
from .change import GenericChange, SuperChange
from .change import Addition, Removal
from .digests import NAMED_DIGESTS, digests_stream, UnsupportedDigest
from .dirutils import fnmatches, makedirsp


__all__ = (
    "ManifestChange", "ManifestSectionChange",
    "ManifestSectionAdded", "ManifestSectionRemoved",
    "Manifest", "ManifestSection",
    "SignatureManifest",
    "ManifestKeyException", "MalformedManifest",
    "main", "cli",
    "cli_create", "cli_query", "cli_sign",
)


class ManifestKeyException(Exception):
    """
    Indicates there was an issue with the key used in a manifest
    section
    """
    pass


class MalformedManifest(Exception):
    """
    Indicates there was a problem in parsing a manifest
    """
    pass


class ManifestSectionChange(GenericChange):
    label = "Manifest Subsection"


    def get_description(self):
        m = self.ldata or self.rdata
        entry = m.primary()
        if self.is_change():
            return "%s Changed: %s" % (self.label, entry)
        else:
            return "%s Unchanged: %s" % (self.label, entry)


    def is_ignored(self, options):
        if getattr(options, "ignore_manifest_subsections", False):
            return True

        ikeys = set(getattr(options, "ignore_manifest_key", set()))
        if ikeys:
            lset = set(self.ldata.items())
            rset = set(self.rdata.items())
            changed = set(k for k,v in lset.symmetric_difference(rset))
            return changed.issubset(ikeys)

        else:
            return False


class ManifestSectionAdded(ManifestSectionChange, Addition):

    label = "Manifest Subsection Added"

    def get_description(self):
        return "%s: %s" % (self.label, self.rdata.primary())


    def is_ignored(self, options):
        return getattr(options, "ignore_manifest_subsections", False)


class ManifestSectionRemoved(ManifestSectionChange, Removal):

    label = "Manifest Subsection Removed"

    def get_description(self):
        return "%s: %s" % (self.label, self.ldata.primary())


    def is_ignored(self, options):
        return getattr(options, "ignore_manifest_subsections", False)


class ManifestMainChange(GenericChange):

    label = "Manifest Main Section"


    def get_description(self):
        if self.is_change():
            return "%s has changed" % self.label
        else:
            return "%s is unchanged" % self.label


    def is_ignored(self, options):
        ikeys = set(getattr(options, "ignore_manifest_key", set()))
        if ikeys:
            lset = set(self.ldata.items())
            rset = set(self.rdata.items())
            changed = set(k for k,v in lset.symmetric_difference(rset))
            return changed.issubset(ikeys)

        else:
            return False


class ManifestChange(SuperChange):

    label = "Manifest"


    def collect_impl(self):
        lm, rm = self.ldata, self.rdata
        yield ManifestMainChange(lm, rm)

        l_sections = set(lm.sub_sections.keys())
        r_sections = set(rm.sub_sections.keys())

        for s in l_sections.intersection(r_sections):
            yield ManifestSectionChange(lm.sub_sections[s], rm.sub_sections[s])

        for s in l_sections.difference(r_sections):
            yield ManifestSectionRemoved(lm.sub_sections[s], None)

        for s in r_sections.difference(l_sections):
            yield ManifestSectionAdded(None, rm.sub_sections[s])


    def is_ignored(self, options):
        return getattr(options, "ignore_manifest", False) or \
            SuperChange.is_ignored(self, options)


class ManifestSection(OrderedDict):

    primary_key = "Name"


    def __init__(self, name=None):
        OrderedDict.__init__(self)
        self[self.primary_key] = name


    def __setitem__(self, k, v):
        #pylint: disable=W0221
        # we want the behavior of OrderedDict, but don't take the
        # additional parameter

        # our keys should always be strings, as should our values. We
        # also have an upper limit on the length we can permit for
        # keys, per the JAR MANIFEST specification.
        k = str(k)
        if len(k) > 68:
            raise ManifestKeyException("key too long", k)
        else:
            OrderedDict.__setitem__(self, k, str(v))


    def primary(self):
        """
        The primary value for this section
        """

        return self.get(self.primary_key)


    def load(self, items):
        """
        Populate this section from an iteration of the parse_items call
        """

        for k,vals in items:
            self[k] = "".join(vals)


    def store(self, stream, linesep=os.linesep):
        """
        Serialize this section and write it to a stream
        """

        for k, v in self.items():
            write_key_val(stream, k, v, linesep)

        stream.write(linesep)


    def get_data(self, linesep=os.linesep):
        """
        Serialize the section and return it as a string
        """

        stream = StringIO()
        self.store(stream, linesep)
        return stream.getvalue()


    def keys_with_suffix(self, suffix):
        """
        :return: list of keys ending with given :suffix:.
        """
        return [k.rstrip(suffix) for k in self.keys() if k.endswith(suffix)]


    def verify(self, jarinfo):
        """
        Verify all digests in this section against the matching entry in
        the given JarInfo instance.

        Returns
        -------
        result : `int` -1 indicating a mismatched digest, 0 indicating
          no supported digests, or a positive number indicating the
          count of supported digests which matched.
        """

        pass


class Manifest(ManifestSection):
    """
    Represents a Java Manifest as an ordered dictionary containing
    the key:value pairs from the main section of the manifest, and
    zero or more sub-dictionaries of key:value pairs representing the
    sections following the main section. The sections are referenced
    by the value of their 'Name' pair, which must be unique to the
    Manifest as a whole.
    """

    primary_key = "Manifest-Version"


    def __init__(self, version="1.0", linesep=None):
        # can't use super, because we're a child of a non-object
        ManifestSection.__init__(self, version)
        self.sub_sections = OrderedDict([])
        self.linesep = linesep


    def create_section(self, name, overwrite=True):
        """
        create and return a new sub-section of this manifest, with the
        given Name attribute. If a sub-section already exists with
        that name, it will be lost unless overwrite is False in which
        case the existing sub-section will be returned.
        """

        if overwrite:
            sect = ManifestSection(name)
            self.sub_sections[name] = sect

        else:
            sect = self.sub_sections.get(name, None)
            if sect is None:
                sect = ManifestSection(name)
                self.sub_sections[name] = sect

        return sect


    def parse_file(self, filename):
        """
        Parse the given file, and attempt to detect the line separator.
        """

        with open(filename, "r", _BUFFERING) as stream:
            self.parse(stream)


    def parse(self, data):
        """
        populate instance with values and sub-sections from data in a
        stream, string, or buffer
        """

        self.linesep = detect_linesep(data)

        # the first section is the main one for the manifest. It's
        # also where we will check for our newline seperator
        sections = parse_sections(data)
        self.load(sections.next())

        # and all following sections are considered sub-sections
        for section in sections:
            next_section = ManifestSection(None)
            next_section.load(section)
            self.sub_sections[next_section.primary()] = next_section


    def store(self, stream, linesep=None):
        """
        Serialize the Manifest to a stream
        """

        # either specified here, specified on the instance, or the OS
        # default
        linesep = linesep or self.linesep or os.linesep

        ManifestSection.store(self, stream, linesep)
        for sect in sorted(self.sub_sections.values()):
            sect.store(stream, linesep)


    def get_main_section(self, linesep=None):
        """
        Serialize just the main section of the manifest and return it as a
        string
        """

        linesep = linesep or self.linesep or os.linesep

        stream = StringIO()
        ManifestSection.store(self, stream, linesep)
        return stream.getvalue()


    def get_data(self, linesep=None):
        """
        Serialize the entire manifest and return it as a string
        """

        linesep = linesep or self.linesep or os.linesep

        stream = StringIO()
        self.store(stream, linesep)
        return stream.getvalue()


    def clear(self):
        """
        removes all items from this manifest, and clears and removes all
        sub-sections
        """

        for sub in self.sub_sections.values():
            sub.clear()
        self.sub_sections.clear()

        ManifestSection.clear(self)


    def __del__(self):
        self.clear()


    def verify(self, jarinfo):
        """
        Verifies the entries in this manifest against the entries in the
        JarInfo instance.

        Returns
        -------
        result : `int` -1 indicating a mistmatched entry, 0 indicating
          no matching entries, or a positive value indicating the number of
          entries successfully verified
        """

        pass


def detect_linesep(data):
    if isinstance(data, (str, buffer)):
        data = StringIO(data)

    offset = data.tell()
    line = data.readline()
    data.seek(offset)

    if line[-2:] == "\r\n":
        return "\r\n"
    elif line[-1] in "\r\n":
        return line[-1]
    else:
        # if there is no line separator in the file to detect
        return os.linesep


def parse_sections(data):
    """
    yields one section at a time in the form

    [ (key, [val, ...]), ... ]

    where key is a string and val is a string representing a single
    line of any value associated with the key. Multiple vals may be
    present if the value is long enough to require line continuations
    in which case simply concatenate the vals together to get the full
    value.
    """

    if not data:
        return

    if isinstance(data, (str, buffer)):
        data = StringIO(data)

    # our current section
    curr = None

    for lineno,line in enumerate(data):
        # Clean up the line
        cleanline = line.splitlines()[0].replace('\x00', '')

        if not cleanline:
            # blank line means end of current section (if any)
            if curr:
                yield curr
                curr = None

        elif cleanline[0] == ' ':
            # line beginning with a space means a continuation
            if curr is None:
                raise MalformedManifest("bad line continuation, "
                                        " line: %i" % lineno)
            else:
                curr[-1][1].append(cleanline[1:])

        else:
            # otherwise the beginning of a new k:v pair
            if curr is None:
                curr = list()

            key, val = cleanline.split(':', 1)
            curr.append((key, [val[1:]]))

    # yield and leftovers
    if curr:
        yield curr


def write_key_val(stream, key, val, linesep=os.linesep):
    """
    The MANIFEST specification limits the width of individual lines to
    72 bytes (including the terminating newlines). Any key and value
    pair that would be longer must be split up over multiple
    continuing lines
    """

    key = key or ""
    val = val or ""

    if not (0 < len(key) < 69):
        raise ManifestKeyException("bad key length", key)

    if len(key) + len(val) > 68:
        kvbuffer = StringIO(": ".join((key, val)))

        # first grab 70 (which is 72 after the trailing newline)
        stream.write(kvbuffer.read(70))

        # now only 69 at a time, because we need a leading space and a
        # trailing \n
        part = kvbuffer.read(69)
        while part:
            stream.write(linesep + " ")
            stream.write(part)
            part = kvbuffer.read(69)
        kvbuffer.close()

    else:
        stream.write(key)
        stream.write(": ")
        stream.write(val)

    stream.write(linesep)


def directory_generator(dirname, trim=0):
    """
    emits (filename, open_f) for every file entry relative to dirname.
    open_f is a function that can be called to open a stream to read
    the given entry.
    """

    def gather(collect, dirname, fnames):
        for fname in fnames:
            df = join(dirname, fname)
            if not isdir(df):
                collect.append(df)

    collect = list()
    walk(dirname, gather, collect)
    for fname in collect:
        yield fname[trim:], partial(open, fname, "rb")


def multi_path_generator(pathnames):
    """
    emits (name, open_f) for all of the files found under the list of
    pathnames given. This is recursive, so directories will have their
    contents emitted. open_f is a function that can called to open a
    stream to read the given entry.
    """

    for pathname in pathnames:
        if isdir(pathname):
            for entry in directory_generator(pathname):
                yield entry
        else:
            yield pathname, partial(open, pathname, "rb")


def single_path_generator(pathname):
    """
    emits (name, open_f) pairs for the given file at pathname. If
    pathname is a directory, will act recursively and will emit for
    each file in the directory tree. open_f is a function that can be
    called to open a stream to read the given entry.
    """

    if isdir(pathname):
        trim = len(pathname)
        if pathname[-1] != sep:
            trim += 1
        for entry in directory_generator(pathname, trim):
            yield entry

    else:
        zf = ZipFile(pathname)
        for f in zf.namelist():
            if f[-1] != '/':
                yield f, partial(zf.open, f)
        zf.close()


def cli_create(options, rest):
    """
    command-line call to create a manifest from a JAR file or a
    directory
    """

    if len(rest) != 2:
        print "Usage: manifest --create [-r|--recursive]" \
              " [-i|--ignore pattern] [-d|--digest algo]" \
              " [-m manifest] file|directory"
        return 1

    digests = options.digests or ['MD5', 'SHA1']
    try:
        for dig in digests:
            lookup_digest(dig)
    except UnsupportedDigest:
        print "Unknown digest algorithm %r" % dig
        print "Supported algorithms:", ",".join(sorted(NAMED_DIGESTS.keys()))
        return 1

    if options.recursive:
        entries = multi_path_generator(rest[1:])
    else:
        entries = single_path_generator(rest[1])

    mf = Manifest()

    ignores = options.ignore

    for name, open_f in entries:
        # skip the stuff that we were told to ignore
        if ignores and fnmatches(name, *ignores):
            continue

        sec = mf.create_section(name)

        with open_f() as fd:
            digs = digests_stream(fd, requested_digests)

        for digest_name, digest_value in izip(requested_digests, digs):
            sec[digest_name + "-Digest"] = digest_value

    output = sys.stdout
    if options.manifest:
        # we'll output to the manifest file if specified, and we'll
        # even create parent directories for it, if necessary
        makedirsp(split(options.manifest)[0])
        output = open(options.manifest, "w")

    mf.store(output)

    if options.manifest:
        output.close()


def cli_query(options, rest):
    if(len(rest) != 2):
        print "Usage: manifest --query=key file.jar"
        return 1

    with JarInfo(rest[1]) as jf:
        mf = jf.get_manifest()

    for q in options.query:
        s = q.split(':', 1)
        if(len(s) > 1):
            mfs = mf.sub_sections.get(s[0])
            if mfs:
                print q, "=", mfs.get(s[1])
            else:
                print q, ": No such section"

        else:
            print q, "=", mf.get(s[0])


def cli_verify(options, rest):
    """
    Command-line wrapper around verify()
    """

    if len(rest) != 4:
        print "Usage: manifest --verify certificate.pem file.jar key_alias"
        return 1

    certificate = rest[1]
    jar_file = rest[2]
    key_alias = rest[3]
    result_message = verify(certificate, jar_file, key_alias)
    if result_message is not None:
        print result_message
        return 1
    print "Jar verified."
    return 0


def cli_sign(options, rest):
    """
    Signs the jar (almost) identically to jarsigner.
    """

    # TODO: move this into jarutil, since it actually modifies a JAR
    # file. We can leave the majority of the signing implementation in
    # this module, but anything that modifies a JAR should wind up in
    # jarutil.

    if len(rest) != 5:
        print "Usage: \
            manifest --sign certificate private_key key_alias file.jar"
        return 1

    certificate = rest[1]
    private_key = rest[2]
    key_alias = rest[3]
    jar_file = ZipFile(rest[4], "a")
    if not "META-INF/MANIFEST.MF" in jar_file.namelist():
        print "META-INF/MANIFEST.MF not found in the JAR"
        return 1

    mf = Manifest()
    mf.parse(jar_file.read("META-INF/MANIFEST.MF"))

    # create a signature manifest, and make it match the line separator
    # style of the manifest it'll be digesting.
    sf = SignatureManifest(linesep=mf.linesep)
    sf.digest_manifest(mf, "SHA-256")   # TODO: option for other algorithms
    jar_file.writestr("META-INF/" + key_alias + ".SF", sf.get_data())
    jar_file.writestr("META-INF/" + key_alias + ".RSA",
                      sf.get_signature(certificate, private_key))

    return 0


def cli(options, rest):
    if options.verify:
        return cli_verify(options, rest)

    elif options.create:
        return cli_create(options, rest)

    elif options.query:
        return cli_query(options, rest)

    elif options.sign:
        return cli_sign(options, rest)

    else:
        print "specify one of --verify, --query, --sign, or --create"
        return 0


def create_optparser():
    from optparse import OptionParser

    parse = OptionParser(usage="Create, sign or verify a MANIFEST for"
                         " a JAR, ZIP, or directory")

    parse.add_option("-v", "--verify", action="store_true")
    parse.add_option("-c", "--create", action="store_true")
    parse.add_option("-q", "--query", action="append",
                     default=[],
                     help="Query the manifest for keys")
    parse.add_option("-r", "--recursive", action="store_true")
    parse.add_option("-m", "--manifest", action="store", default=None,
                     help="manifest file, default is stdout for create"
                     " or the argument-relative META-INF/MANIFEST.MF"
                     " for verify.")
    parse.add_option("-i", "--ignore", action="append",
                     default=["META-INF/*"],
                     help="patterns to ignore when creating or checking"
                     " files")
    parse.add_option("-d", "--digest", action="append", default=[],
                     help="digest algorithms to use in the manifest. Can be"
                     " specified multiple times. If unspecified, MD5 and"
                     " SHA-1 will be used")
    parse.add_option("-s", "--sign", action="store_true",
                     help="sign the JAR file with OpenSSL"
                     " (must be followed with: "
                     "certificate.pem, private_key.pem, key_alias)")
    return parse


def main(args):
    """
    main entry point for the manifest CLI
    """

    parser = create_optparser()
    return cli(*parser.parse_args(args))


#
# The end.
