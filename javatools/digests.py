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
digest utilities for python-javatools

:author: Christopher O'Brien  <obriencj@gmail.com>
:license: LGPL v.3
"""


import hashlib

from . import _BUFFERING


__all__ = (
    "NAMED_DIGESTS", "UnsupportedDigest",
    "register_digest", "lookup_digest",
    "digest_stream", "digest_chunks",
)


class UnsupportedDigest(Exception):
    """
    Indicates an algorithm was requested for which we had no matching
    digest support
    """
    pass


# Digests classes by Java name that have been found present in hashlib
NAMED_DIGESTS = {}


def _add_digest(java_name, hashlib_name):
    digest = getattr(hashlib, hashlib_name, None)
    if digest:
        NAMED_DIGESTS[java_name] = digest


def register_digest(java_name, digest_class):
    """
    Registers a digest implementation by its Java-style name for later
    use.
    """

    NAMED_DIGESTS[java_name] = digest_class


def lookup_digest(java_name):
    """
    Get a registered digest class by its Java-style name. Raises an
    `UnsupportedDigest` exception if there is no matching digest
    registered
    """

    try:
        return NAMED_DIGESTS[java_name]
    except KeyError:
        raise UnsupportedDigest(java_name)


# Note 1: Java supports also MD2, but hashlib does not
_add_digest("MD2", "md2")
_add_digest("MD5", "md5")

# Note 2: Oracle specifies "SHA-1" algorithm name in their
# documentation, but it's called "SHA1" elsewhere and that is what
# jarsigner uses as well.
_add_digest("SHA1", "sha1")
_add_digest("SHA-256", "sha256")
_add_digest("SHA-384", "sha384")
_add_digest("SHA-512", "sha512")


def digest(data, digest_name='SHA-256', encoding='base64'):
    dig = lookup_digest(digest_name)()
    dig.update(chunk)
    result = dig.digest().encode(encoding)

    # the base64 encoding -- and only the base64 encoding -- appends a
    # trailing \n character. Filter that out.
    if encoding == "base64":
        result = result[:-1]

    return result


def digests_data(data, digest_names=('MD5', 'SHA-256'),
                encoding="base64"):

    return tuple(digest(data,dn,encoding) for dn in digest_names)


def digests_stream(stream, buffering=_BUFFERING,
                  digest_names=('MD5', 'SHA-256'), encoding="base64"):

    """
    Digests a stream of data into a number of hashes at once.
    """

    return digests_chunks(iter(partial(stream.read, buffering), ''),
                          digest_names, encoding)


def digests_chunks(chunk_iter, digest_names=('MD5', 'SHA-256'),
                   encoding="base64"):
    """
    Digests chunks of data into a number of hashes at once.

    Parameters
    ----------
    chunk_iter : sequence of strings
      iterable series of strings representing the data to be hashed
    digest_names : `tuple`, default ('MD5', 'SHA-256')
      the Java names of the hash algorithms to calculate
    encoding : `str`, default "base64"
      encoding to represent the final digests in

    Returns
    -------
    hashes : `tuple` of `str`
      encoded to the `encoding` specified (default base64), in the
      same order as specified by `digest_names`

    Raises
    ------
    exception : `UnsupportedDigest`
      when an unknown digest is specified in `digest_names`
    """

    digests = [lookup_digest(name)() for name in digest_names]
    for chunk in chunk_iter:
        for dig in digests:
            dig.update(chunk)

    results = (dig.digest().encode(encoding) for dig in digests)

    # the base64 encoding -- and only the base64 encoding -- appends a
    # trailing \n character. Filter that out.
    if encoding == "base64":
        results = (result[:-1] for result in results)

    return tuple(results)


#
# The end.
