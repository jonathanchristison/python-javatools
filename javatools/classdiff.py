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
Module for comparing the internals of two Java class files
for differences in structure and data. Has options to specify changes
which may be immaterial or unimportant, such as re-ordering of the
constant pool, line number changes (either absolute or relative),
added fields or methods, deprecation changes, etc.

:author: Christopher O'Brien  <obriencj@gmail.com>
:license: LGPL
"""


from abc import ABCMeta
from itertools import izip
from javatools import unpack_classfile
from .change import GenericChange, SuperChange
from .change import Addition, Removal
from .change import yield_sorted_by_type
from .opcodes import get_opname_by_code, has_const_arg


__all__ = (
    "JavaClassChange",
    "ClassInfoChange",
    "ClassAnnotationsChange",
    "ClassInvisibleAnnotationsChange",
    "ClassConstantPoolChange",
    "ClassFieldsChange", "ClassMethodsChange",

    "ClassMembersChange",
    "MemberSuperChange", "MemberAdded", "MemberRemoved",

    "FieldChange", "FieldAdded", "FieldRemoved",
    "FieldNameChange", "FieldTypeChange",
    "FieldSignatureChange", "FieldAnnotationsChange",
    "FieldInvisibleAnnotationsChange",
    "FieldAccessflagsChange", "FieldConstvalueChange",
    "FieldDeprecationChange",

    "MethodChange", "MethodAdded", "MethodRemoved",
    "MethodNameChange", "MethodTypeChange",
    "MethodSignatureChange", "MethodAnnotationsChange",
    "MethodInvisibleAnnotationsChange",
    "MethodParametersChange", "MethodAccessflagsChange",
    "MethodExceptionsChange",
    "MethodAbstractChange", "MethodCodeChange",
    "MethodDeprecationChange",

    "CodeAbsoluteLinesChange",
    "CodeRelativeLinesChange",
    "CodeStackChange",
    "CodeLocalsChange",
    "CodeExceptionChange",
    "CodeConstantsChange",
    "CodeBodyChange",

    "JavaClassReport",

    "pretty_merge_constants", "merge_code",
    "default_classdiff_options",
)


class ClassNameChange(GenericChange):

    label = "Class name"


    def fn_data(self, c):
        return c.get_this()


    def fn_pretty(self, c):
        return c.pretty_this()


class ClassVersionChange(GenericChange):

    label = "Java class verison"


    def fn_data(self, c):
        return c.version


    def is_ignored(self, o):
        lver = self.ldata.version
        rver = self.rdata.version

        return ((o.ignore_version_up and lver < rver) or
                (o.ignore_version_down and lver > rver))


class ClassPlatformChange(GenericChange):

    label = "Java platform"


    def fn_data(self, c):
        return c.get_platform()


    def is_ignored(self, o):
        lver = self.ldata.version
        rver = self.rdata.version

        return ((o.ignore_version_up and lver < rver) or
                (o.ignore_version_down and lver > rver))


class ClassSuperclassChange(GenericChange):

    label = "Superclass"


    def fn_data(self, c):
        return c.get_super()


    def fn_pretty(self, c):
        return c.pretty_super()


class ClassInterfacesChange(GenericChange):

    label = "Interfaces"


    def fn_data(self, c):
        return set(c.get_interfaces())


    def fn_pretty(self, c):
        return tuple(c.pretty_interfaces())


class ClassAccessflagsChange(GenericChange):

    label = "Access flags"


    def fn_data(self, c):
        return c.access_flags


    def fn_pretty(self, c):
        return tuple(c.pretty_access_flags())


class ClassDeprecationChange(GenericChange):

    label = "Deprecation"


    def fn_data(self, c):
        return c.is_deprecated()


    def is_ignored(self, o):
        return o.ignore_deprecated


class ClassSignatureChange(GenericChange):

    label = "Generics Signature"


    def fn_data(self, c):
        return c.get_signature()


    def fn_pretty(self, c):
        return c.pretty_signature()


class AnnotationsChange(GenericChange):

    __metaclass__ = ABCMeta

    label = "Runtime annotations"


    def fn_data(self, c):
        return c.get_annotations() or tuple()


    def fn_pretty(self, c):
        annos = self.fn_data(c)
        return [anno.pretty_annotation() for anno in annos]


class InvisibleAnnotationsChange(AnnotationsChange):

    __metaclass__ = ABCMeta

    label = "Runtime Invisible annotations"


    def fn_data(self, c):
        return c.get_invisible_annotations() or tuple()


class ClassAnnotationsChange(AnnotationsChange):

    label = "Class runtime annotations"


class ClassInvisibleAnnotationsChange(InvisibleAnnotationsChange):

    label = "Class runtime invisible annotations"


class ClassInfoChange(SuperChange):

    label = "Class information"


    change_types = (ClassNameChange,
                    ClassVersionChange,
                    ClassPlatformChange,
                    ClassSuperclassChange,
                    ClassInterfacesChange,
                    ClassAccessflagsChange,
                    ClassDeprecationChange,
                    ClassSignatureChange)


class MemberSuperChange(SuperChange):
    """
    basis for FieldChange and MethodChange
    """

    __metaclass__ = ABCMeta

    label = "Member"


    def get_description(self):
        return "%s: %s" % (self.label, self.ldata.pretty_descriptor())


class MemberAdded(Addition):
    """
    basis for FieldAdded and MethodAdded
    """

    __metaclass__ = ABCMeta

    label = "Member added"


    def get_description(self):
        return "%s: %s" % (self.label, self.rdata.pretty_descriptor())


class MemberRemoved(Removal):
    """
    basis for FieldChange and MethodChange
    """

    __metaclass__ = ABCMeta

    label = "Member removed"


    def get_description(self):
        return "%s: %s" % (self.label, self.ldata.pretty_descriptor())


class ClassMembersChange(SuperChange):
    """
    basis for ClassFieldsChange and ClassMethodsChange
    """

    __metaclass__ = ABCMeta

    label = "Members"

    member_added = MemberAdded
    member_removed = MemberRemoved
    member_changed = MemberSuperChange


    def collect_impl(self):
        li = {}

        for member in self.ldata:
            li[member.get_identifier()] = member

        for member in self.rdata:
            key = member.get_identifier()
            lf = li.get(key, None)

            if lf:
                del li[key]
                yield self.member_changed(lf, member)
            else:
                yield self.member_added(None, member)

        for member in li.values():
            yield self.member_removed(member, None)


class CodeAbsoluteLinesChange(GenericChange):

    label = "Absolute line numbers"


    def fn_data(self, c):
        return c.get_linenumbertable() if c else tuple()


    def is_ignored(self, options):
        return options.ignore_absolute_lines


class CodeRelativeLinesChange(GenericChange):

    label = "Relative line numbers"


    def fn_data(self, c):
        return c.get_relativelinenumbertable() if c else tuple()


    def is_ignored(self, options):
        return options.ignore_relative_lines


class CodeStackChange(GenericChange):

    label = "Stack size"


    def fn_data(self, c):
        return c.max_stack if c else 0


class CodeLocalsChange(GenericChange):

    label = "Locals"


    def fn_data(self, c):
        return c.max_locals if c else 0


class CodeExceptionChange(GenericChange):

    label = "Exception table"


    def fn_data(self, c):
        return c.exceptions if c else tuple()


    def fn_pretty(self, c):
        a = list()
        for e in self.fn_data(c):
            p = (e.start_pc, e.end_pc,
                 e.handler_pc, e.pretty_catch_type())
            a.append(p)
        return repr(a)


class CodeConstantsChange(GenericChange):
    """
    This is a test to find instances where the individual opcodes and
    arguments for a method's code may all be identical except that ops
    which load from the constant pool may use a different index. We
    will deref the constant index for both sides, and if all of the
    constant values match then we can consider the code to be equal.

    The purpose of such a check is to find other-wise meaningless
    constant pool reordering. If all uses of the pool result in the
    same values, we don't really care if the pool is in a different
    order between the old and new versions of a class.
    """

    label = "Code constants"


    def __init__(self, lcode, rcode):
        super(CodeConstantsChange, self).__init__(lcode, rcode)
        self.offsets = None


    def fn_pretty(self, c):
        if not self.offsets:
            return None

        pr = list()

        for offset, code, args in c.disassemble():
            if offset in self.offsets and has_const_arg(code):
                name = get_opname_by_code(code)
                data = c.cpool.pretty_deref_const(args[0])
                pr.append((offset, name, data))

        return pr


    def check_impl(self):
        left = self.ldata
        right = self.rdata
        offsets = list()

        if left is None or right is None:
            return True, None

        if len(left.code) != len(right.code):
            # code body change, can't determine constants
            return True, None

        for l, r in izip(left.disassemble(), right.disassemble()):
            if not ((l[0] == r[0]) and (l[1] == r[1])):
                # code body change, can't determine constants
                return True, None

            largs = l[2]
            rargs = r[2]

            if has_const_arg(l[1]):
                largs = list(largs)
                rargs = list(rargs)
                largs[0] = left.cpool.deref_const(largs[0])
                rargs[0] = right.cpool.deref_const(rargs[0])

            if largs != rargs:
                offsets.append(l[0])

        self.offsets = offsets
        return bool(self.offsets), None


class CodeBodyChange(GenericChange):
    """
    The length or the opcodes or the arguments of the opcodes has
    changed, signalling that the method body is different
    """

    label = "Code body"


    def fn_data(self, c):
        return c.disassemble() if c else tuple()


    def fn_pretty(self, c):
        pr = list()
        for offset, code, args in self.fn_data(c):
            name = get_opname_by_code(code)
            pr.append((offset, name, args))

        return pr


    def check_impl(self):
        left = self.ldata
        right = self.rdata

        if left is None or right is None:
            return True, None

        if len(left.code) != len(right.code):
            desc = "Code length changed from %r to %r" % \
                   (len(left.code), len(right.code))
            return True, desc

        for l, r in izip(left.disassemble(), right.disassemble()):
            if not ((l[0] == r[0]) and (l[1] == r[1])):
                return True, None

        return False, None


class MethodNameChange(GenericChange):

    label = "Method name"


    def fn_data(self, c):
        return c.get_name()


class MethodTypeChange(GenericChange):

    label = "Method type"


    def fn_data(self, c):
        return c.get_type_descriptor()


    def fn_pretty(self, c):
        return c.pretty_type()


class MethodSignatureChange(GenericChange):

    label = "Method generic signature"


    def fn_data(self, c):
        return c.get_signature()


    def fn_pretty(self, c):
        return c.pretty_signature()


class MethodParametersChange(GenericChange):

    label = "Method parameters"


    def fn_data(self, c):
        return c.get_arg_type_descriptors()


    def fn_pretty(self, c):
        return tuple(c.pretty_arg_types())


class MethodAccessflagsChange(GenericChange):

    label = "Method accessflags"


    def fn_data(self, c):
        return c.access_flags


    def fn_pretty(self, c):
        return tuple(c.pretty_access_flags())


class MethodAbstractChange(GenericChange):

    label = "Method abstract"


    def fn_data(self, c):
        return not c.get_code()


    def fn_pretty_desc(self, c):
        if self.fn_data(c):
            return "Method is abstract"
        else:
            return "Method is concrete"


class MethodExceptionsChange(GenericChange):

    label = "Method exceptions"


    def fn_data(self, c):
        return c.get_exceptions()


    def fn_pretty(self, c):
        return tuple(c.pretty_exceptions())


class MethodCodeChange(SuperChange):

    label = "Method Code"


    change_types = (CodeAbsoluteLinesChange,
                    CodeRelativeLinesChange,
                    CodeStackChange,
                    CodeLocalsChange,
                    CodeExceptionChange,
                    CodeConstantsChange,
                    CodeBodyChange)


    def __init__(self, l, r):
        super(MethodCodeChange, self).__init__(l.get_code(),
                                               r.get_code())


    def collect_impl(self):
        # if both sides are abstract, don't bother collecting subchanges

        if self.ldata == self.rdata == None:
            return tuple()
        else:
            return super(MethodCodeChange, self).collect_impl()


    def check_impl(self):
        # if one side has gone abstract, don't bother trying to check
        # any deeper, they're different unless they're both abstract.

        if None in (self.ldata, self.rdata):
            return (self.ldata != self.rdata), None
        else:
            return super(MethodCodeChange, self).check_impl()


class MethodDeprecationChange(GenericChange):

    label = "Method deprecation"


    def fn_data(self, c):
        return c.is_deprecated()


    def is_ignored(self, o):
        return o.ignore_deprecated


class MethodAnnotationsChange(AnnotationsChange):

    label = "Method runtime annotations"


class MethodInvisibleAnnotationsChange(InvisibleAnnotationsChange):

    label = "Method runtime invisible annotations"


class MethodChange(MemberSuperChange):

    label = "Method"


    change_types = (MethodNameChange,
                    MethodTypeChange,
                    MethodSignatureChange,
                    MethodAnnotationsChange,
                    MethodInvisibleAnnotationsChange,
                    MethodParametersChange,
                    MethodAccessflagsChange,
                    MethodExceptionsChange,
                    MethodAbstractChange,
                    MethodDeprecationChange,
                    MethodCodeChange)


class FieldNameChange(GenericChange):

    label = "Field name"


    def fn_data(self, c):
        return c.get_name()


class FieldTypeChange(GenericChange):

    label = "Field type"


    def fn_data(self, c):
        return c.get_descriptor()


    def fn_pretty(self, c):
        return c.pretty_type()


class FieldSignatureChange(GenericChange):

    label = "Field Generic Signature"


    def fn_data(self, c):
        return c.get_signature()


    def fn_pretty(self, c):
        return c.pretty_signature()


class FieldAccessflagsChange(GenericChange):

    label = "Field accessflags"


    def fn_data(self, c):
        return c.access_flags


    def fn_pretty(self, c):
        return tuple(c.pretty_access_flags())


    def fn_pretty_desc(self, c):
        return ",".join(c.pretty_access_flags())


class FieldConstvalueChange(GenericChange):

    label = "Field constvalue"


    def fn_data(self, c):
        return c.deref_constantvalue()


    def fn_pretty(self, c):
        return repr(c.deref_constantvalue())


class FieldDeprecationChange(GenericChange):

    label = "Field deprecation"


    def fn_data(self, c):
        return c.is_deprecated()


    def is_ignored(self, o):
        return o.ignore_deprecated


class FieldAnnotationsChange(AnnotationsChange):

    label = "Field runtime annotations"


class FieldInvisibleAnnotationsChange(InvisibleAnnotationsChange):

    label = "Field runtime invisible annotations"


class FieldChange(MemberSuperChange):

    label = "Field"


    change_types = (FieldNameChange,
                    FieldTypeChange,
                    FieldSignatureChange,
                    FieldAnnotationsChange,
                    FieldInvisibleAnnotationsChange,
                    FieldAccessflagsChange,
                    FieldConstvalueChange,
                    FieldDeprecationChange)


class FieldAdded(MemberAdded):

    label = "Field added"


class FieldRemoved(MemberRemoved):

    label = "Field removed"


class ClassFieldsChange(ClassMembersChange):

    label = "Fields"


    member_added = FieldAdded
    member_removed = FieldRemoved
    member_changed = FieldChange


    @yield_sorted_by_type(FieldAdded, FieldRemoved, FieldChange)
    def collect_impl(self):
        return super(ClassFieldsChange, self).collect_impl()


    def __init__(self, lclass, rclass):
        super(ClassFieldsChange, self).__init__(lclass.fields,
                                                rclass.fields)


class MethodAdded(MemberAdded):

    label = "Method added"


class MethodRemoved(MemberRemoved):

    label = "Method removed"


class ClassMethodsChange(ClassMembersChange):

    label = "Methods"


    member_added = MethodAdded
    member_removed = MethodRemoved
    member_changed = MethodChange


    @yield_sorted_by_type(MethodAdded, MethodRemoved, MethodChange)
    def collect_impl(self):
        return super(ClassMethodsChange, self).collect_impl()


    def __init__(self, lclass, rclass):
        super(ClassMethodsChange, self).__init__(lclass.methods,
                                                 rclass.methods)


class ClassConstantPoolChange(GenericChange):

    label = "Constant pool"


    def fn_data(self, c):
        return c.cpool


    def fn_pretty(self, c):
        return tuple(c.cpool.pretty_constants())


    def is_ignored(self, options):
        return options.ignore_pool


    def get_description(self):
        return self.label + ((" unaltered", " altered")[self.is_change()])


class JavaClassChange(SuperChange):

    label = "Java Class"


    change_types = (ClassInfoChange,
                    ClassAnnotationsChange,
                    ClassInvisibleAnnotationsChange,
                    ClassConstantPoolChange,
                    ClassFieldsChange,
                    ClassMethodsChange)


    def get_description(self):
        return "%s %s" % (self.label, self.ldata.pretty_this())


class JavaClassReport(JavaClassChange):
    """
    a JavaClassChange with the side-effect of writing reports
    """


    def __init__(self, l, r, reporter):
        super(JavaClassReport, self).__init__(l, r)
        self.reporter = reporter


    def check(self):
        super(JavaClassReport, self).check()
        self.reporter.run(self)


# ---- Utility functions ----
#


def pretty_merge_constants(left_cpool, right_cpool):
    """
    sequence of tuples containing (index, left type, left pretty
    value, right type, right pretty value). If the constant pools are
    of inequal length, a value of None will be set in place of the
    type and pretty value for indexes past its end
    """

    lsize = len(left_cpool.consts)
    rsize = len(right_cpool.consts)

    index = 1
    for index in xrange(1, min(lsize, rsize)):
        lt, lv = left_cpool.pretty_const(index)
        rt, rv = right_cpool.pretty_const(index)
        yield (index, lt, lv, rt, rv)

    if lsize > rsize:
        for index in xrange(index, lsize):
            lt, lv = left_cpool.pretty_const(index)
            yield (index, lt, lv, None, None)

    elif rsize > lsize:
        for index in xrange(index, rsize):
            rt, rv = right_cpool.pretty_const(index)
            yield (index, None, None, rt, rv)


def merge_code(left_code, right_code):
    """
    { relative_line:
      ((left_abs_line, ((offset, op, args), ...)),
       (right_abs_line, ((offset, op, args), ...))),
      ... }
    """

    data = dict()

    code_lines = left_code.iter_code_by_lines() if left_code else tuple()
    for abs_line, rel_line, dis in code_lines:
        data[rel_line] = [(abs_line, dis), None]

    code_lines = right_code.iter_code_by_lines() if right_code else tuple()
    for abs_line, rel_line, dis in code_lines:
        found = data.get(rel_line, None)
        if found is None:
            found = [None, (abs_line, dis)]
            data[rel_line] = found
        else:
            found[1] = (abs_line, dis)

    return data


def default_classdiff_options(updates=None):
    """
    generate an options object with the appropriate default values in
    place for API usage of classdiff features. overrides is an
    optional dictionary which will be used to update fields on the
    options object.
    """

    from .cli.classdiff import create_optparser

    parser = create_optparser()
    options, _args = parser.parse_args(list())

    if updates:
        #pylint: disable=W0212
        options._update_careful(updates)

    return options


#
# The end.
