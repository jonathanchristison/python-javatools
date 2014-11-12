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
Command-line utility for fetching information out of a JAR file,
and printing it out.

:author: Christopher O'Brien  <obriencj@gmail.com>
:license: LGPL
"""


from json import dump
from optparse import OptionGroup, OptionParser

from ..jarinfo import JarInfo


__all__ = (
    "main", "cli", "jarinfo_optgroup", )



def cli_jar_manifest_info(options, jarinfo):
    mf = jarinfo.get_manifest()

    if not mf:
        print "Manifest not present."
        print
        return

    print "Manifest main section:"
    for k, v in sorted(mf.items()):
        print "  %s: %s" % (k, v)

    for _name, sect in sorted(mf.sub_sections.items()):
        print
        print "Manifest sub-section:"
        for k, v in sorted(sect.items()):
            print "  %s: %s" % (k, v)

    print


def cli_jar_zip_info(options, jarinfo):
    zipfile = jarinfo.get_zipfile()

    files, dirs, comp, uncomp = zip_entry_rollup(zipfile)
    prcnt = (float(comp)  / float(uncomp)) * 100

    print "Contains %i files, %i directories" % (files, dirs)
    print "Uncompressed size is %i" % uncomp
    print "Compressed size is %i (%0.1f%%)" % (comp, prcnt)
    print


def cli_jar_classes(options, jarinfo):
    for entry in jarinfo.get_classes():
        ci = jarinfo.get_classinfo(entry)
        print "Entry: ", entry
        cli_print_classinfo(options, ci)
        print


def cli_jar_provides(options, jarinfo):
    print "jar provides:"

    for provided in sorted(jarinfo.get_provides().iterkeys()):
        if not fnmatches(provided, *options.api_ignore):
            print " ", provided
    print


def cli_jar_requires(options, jarinfo):
    print "jar requires:"

    for required in sorted(jarinfo.get_requires().iterkeys()):
        if not fnmatches(required, *options.api_ignore):
            print " ", required
    print


def cli_jarinfo(options, info):
    if options.zip:
        cli_jar_zip_info(options, info)

    if options.manifest:
        cli_jar_manifest_info(options, info)

    if options.jar_provides:
        cli_jar_provides(options, info)

    if options.jar_requires:
        cli_jar_requires(options, info)

    if options.jar_classes:
        cli_jar_classes(options, info)


def cli_jarinfo_json(options, info):
    data = {}

    if options.jar_provides:
        data["jar.provides"] = info.get_provides(options.api_ignore)

    if options.jar_requires:
        data["jar.requires"] = info.get_requires(options.api_ignore)

    if options.zip:
        zipfile = info.get_zipfile()
        filec, dirc, totalc, totalu = zip_entry_rollup(zipfile)
        prcnt = (float(totalc)  / float(totalu)) * 100

        data["zip.type"] = zipfile.__class__.__name__
        data["zip.file_count"] = filec
        data["zip.dir_count" ] = dirc
        data["zip.uncompressed_size"] = totalu
        data["zip.compressed_size"] = totalc
        data["zip.compress_percent"] = prcnt

    dump(data, stdout, sort_keys=True, indent=2)


def cli(parser, options, rest):
    if options.verbose:
        options.zip = True
        options.lines = True
        options.locals = True
        options.disassemble = True
        options.sigs = True
        options.constpool = True

    options.indent = not(options.lines or
                         options.disassemble or
                         options.sigs)

    for fn in rest[1:]:
        with JarInfo(filename=fn) as ji:
            if options.json:
                cli_jarinfo_json(options, ji)
            else:
                cli_jarinfo(options, ji)


def jarinfo_optgroup(parser):
    """
    Create and return an `OptionGroup` specifying options relevant to
    presenting information about a Java Archive on the command line.
    """

    g = OptionGroup(parser, "JAR Info Options")

    g.add_option("--zip", action="store_true", default=False,
                 help="print zip information")

    g.add_option("--manifest", action="store_true", default=False,
                 help="print manifest information")

    g.add_option("--jar-classes", action="store_true", default=False,
                 help="print information about contained classes")

    g.add_option("--jar-provides", dest="jar_provides",
                 action="store_true", default=False,
                 help="API provides information at the JAR level")

    g.add_option("--jar-requires", dest="jar_requires",
                 action="store_true", default=False,
                 help="API requires information at the JAR level")

    return g


def create_optparser():
    """
    Create and return an `OptionParser` specifying options relevant to
    presenting information about a Java Archive on the command line.
    """

    from .classinfo import classinfo_optgroup

    parser = OptionParser("%prog [OPTIONS] JARFILE")

    parser.add_option("--json", dest="json", action="store_true",
                      help="output in JSON mode")

    parser.add_option_group(jarinfo_optgroup(parser))
    parser.add_option_group(classinfo_optgroup(parser))

    return parser


def main(args):
    """
    Command-line entry point for the `jarinfo` utility script.
    """

    parser = create_optparser()

    try:
        cli(parser, *parser.parse_args(args))
    except KeyboardInterrupt:
        print
        return 130
    else:
        return 0


#
# The end.
