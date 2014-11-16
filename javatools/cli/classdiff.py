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
Utility script for comparing the internals of two Java class files
for differences in structure and data. Has options to specify changes
which may be immaterial or unimportant, such as re-ordering of the
constant pool, line number changes (either absolute or relative),
added fields or methods, deprecation changes, etc.

:author: Christopher O'Brien  <obriencj@gmail.com>
:license: LGPL
"""


from optparse import OptionGroup, OptionParser
from .report import quick_report, Reporter
from .report import JSONReportFormat, TextReportFormat
from .report import general_report_optgroup
from .report import json_report_optgroup, html_report_optgroup


def cli_classes_diff(parser, options, left, right):
    reports = getattr(options, "reports", tuple())
    if reports:
        rdir = options.report_dir or "./"

        rpt = Reporter(rdir, "JavaClassReport", options)
        rpt.add_formats_by_name(reports)

        delta = JavaClassReport(left, right, rpt)

    else:
        delta = JavaClassChange(left, right)

    delta.check()

    if not options.silent:
        if options.json:
            quick_report(JSONReportFormat, delta, options)
        else:
            quick_report(TextReportFormat, delta, options)

    if (not delta.is_change()) or delta.is_ignored(options):
        return 0
    else:
        return 1


def cli(parser, options, rest):
    if len(rest) != 3:
        parser.error("wrong number of arguments.")

    left = unpack_classfile(rest[1])
    right = unpack_classfile(rest[2])

    return cli_classes_diff(parser, options, left, right)


def classdiff_optgroup(parser):
    """
    option group specific to class checking
    """

    from optparse import OptionGroup

    g = OptionGroup(parser, "Class Checking Options")

    g.add_option("--ignore-version-up", action="store_true", default=False)
    g.add_option("--ignore-version-down", action="store_true", default=False)
    g.add_option("--ignore-platform-up", action="store_true", default=False)
    g.add_option("--ignore-platform-down", action="store_true", default=False)
    g.add_option("--ignore-absolute-lines", action="store_true", default=False)
    g.add_option("--ignore-relative-lines", action="store_true", default=False)
    g.add_option("--ignore-deprecated", action="store_true", default=False)
    g.add_option("--ignore-added", action="store_true", default=False)
    g.add_option("--ignore-pool", action="store_true", default=False)

    g.add_option("--ignore-lines",
                 help="ignore relative and absolute line-number changes",
                 action="callback", callback=_opt_cb_ign_lines)

    g.add_option("--ignore-platform",
                 help="ignore platform changes",
                 action="callback", callback=_opt_cb_ign_platform)

    g.add_option("--ignore-version",
                 help="ignore version changes",
                 action="callback", callback=_opt_cb_ign_version)

    return g


def _opt_cb_ignore(_opt, _opt_str, value, parser):
    """
    handle the --ignore option, which trigges other options
    """

    if not value:
        return

    options = parser.values

    ignore = getattr(options, "ignore", None)
    if ignore is None:
        options.ignore = ignore = list()

    ign = (i.strip() for i in value.split(","))
    ign = (i for i in ign if i)
    for i in ign:
        ignore.append(i)
        iopt_str = "--ignore-" + i.replace("_","-")
        iopt = parser.get_option(iopt_str)
        if iopt:
            iopt.process(iopt_str, value, options, parser)


def _opt_cb_ign_lines(_opt, _opt_str, _value, parser):
    """
    handle the --ignore-lines option
    """

    options = parser.values
    options.ignore_lines = True
    options.ignore_absolute_lines = True
    options.ignore_relative_lines = True


def _opt_cb_ign_version(_opt, _opt_str, _value, parser):
    """
    handle the --ignore-version option
    """

    options = parser.values
    options.ignore_version = True
    options.ignore_version_up = True
    options.ignore_version_down = True


def _opt_cb_ign_platform(_opt, _opt_str, _value, parser):
    """
    handle the --ignore-platform option
    """

    options = parser.values
    options.ignore_platform = True
    options.ignore_platform_up = True
    options.ignore_platform_down = True


def _opt_cb_verbose(_opt, _opt_str, _value, parser):
    """
    handle the --verbose option
    """

    options = parser.values
    options.verbose = True
    options.show_unchanged = True
    options.show_ignored = True


def general_optgroup(parser):
    """
    option group for general-use features of all javatool CLIs
    """

    g = OptionGroup(parser, "General Options")

    g.add_option("-q", "--quiet", dest="silent",
                 action="store_true", default=False)

    g.add_option("-v", "--verbose",
                 action="callback", callback=_opt_cb_verbose)

    g.add_option("-o", "--output", dest="output",
                 action="store", default=None)

    g.add_option("-j", "--json", dest="json",
                 action="store_true", default=False)

    g.add_option("--show-ignored", action="store_true", default=False)
    g.add_option("--show-unchanged", action="store_true", default=False)

    g.add_option("--ignore", type="string",
                 action="callback", callback=_opt_cb_ignore,
                 help="comma-separated list of ignores")

    return g


def create_optparser():
    """
    an OptionParser instance with the appropriate options and groups
    for the classdiff utility
    """

    parser = OptionParser("%prog [OPTIONS] OLD_CLASS NEW_CLASS")

    parser.add_option_group(general_optgroup(parser))
    parser.add_option_group(classdiff_optgroup(parser))

    parser.add_option_group(general_report_optgroup(parser))
    parser.add_option_group(json_report_optgroup(parser))
    parser.add_option_group(html_report_optgroup(parser))

    return parser


def main(args):
    """
    Main entry point for the classdiff CLI
    """

    parser = create_optparser()

    try:
        return cli(parser, *parser.parse_args(args))
    except KeyboardInterrupt:
        print
        return 130


#
# The end.
