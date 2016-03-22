# Copyright (c) 2012-2016 Hewlett Packard Enterprise Development LP
#
# Permission to use, copy, modify, and/or distribute this software for
# any purpose with or without fee is hereby granted, provided that the
# above copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import operator
import sys

try:
    import prettytable
except ImportError:
    pass

from requestbuilder import Arg


class TabifyingMixin(object):
    '''
    A command mixin that provides the tabify() function along with its
    associated --show-empty-fields command line arg.
    '''

    ARGS = [Arg('--show-empty-fields', action='store_true', route_to=None,
                help='show empty values as "(nil)"')]

    def tabify(self, fields, include=None):
        """
        Join a list of strings with tabs.  Nonzero items that Python considers
        false are printed as-is if they appear in the include list, replaced
        with '(nil)' if the user specifies --show-empty-fields at the command
        line, and omitted otherwise.
        """
        if self.args['show_empty_fields']:
            fstr = '(nil)'
        else:
            fstr = ''
        return '\t'.join(str(s) for s in
                         _filter_row_values(fields, fstr, include=include))


class TableOutputMixin(object):
    ARGS = [Arg('--show-headers', action='store_true', route_to=None,
                help='show column headers'),
            Arg('--show-empty-fields', action='store_true', route_to=None,
                help='show empty field values as "(nil)"')]

    def get_table(self, field_names):
        table = _FilteredTable(field_names=field_names,
                               show_empty=self.args.get('show_empty_fields'))
        table.border = False
        table.header = self.args.get('show_headers') or False
        table.header_style = 'upper'
        table.align = 'l'  # left
        table.left_padding_width = 0
        table.right_padding_width = 2
        return table


if 'prettytable' in sys.modules:
    class _FilteredTable(prettytable.PrettyTable):
        def __init__(self, show_empty=False, **kwargs):
            if show_empty:
                self.__empty = '(nil)'
            else:
                self.__empty = ''
            prettytable.PrettyTable.__init__(self, **kwargs)

        def add_row(self, row):
            prettytable.PrettyTable.add_row(
                self, _filter_row_values(row, self.__empty))
else:
    # UglyTable
    class _FilteredTable(object):
        def __init__(self, field_names, show_empty=False):
            self.field_names = field_names
            self.header = False
            self.reversesort = False
            self._rows = []
            self._sortindex = 0
            if show_empty:
                self.__empty = '(nil)'
            else:
                self.__empty = ''

        def add_row(self, row):
            if len(row) != len(self.field_names):
                raise ValueError('row has incorrect number of values '
                                 '({0} given, {1} expected)'
                                 .format(len(row), len(self.field_names)))
            self._rows.append(_filter_row_values(row, self.__empty))

        @property
        def sortby(self):
            return self.field_names[self._sortindex]

        @sortby.setter
        def sortby(self, field):
            self._sortindex = self.field_names.index(field)

        def get_string(self):
            lines = []
            if self.header:
                lines.append('\t'.join(name.upper() for name in
                                       self.field_names))
            for row in sorted(self._rows, reverse=self.reversesort,
                              key=operator.itemgetter(self._sortindex)):
                lines.append('\t'.join(map(str, row)))
            return '\n'.join(lines)

        def __str__(self):
            return self.get_string()


def _filter_row_values(row, empty_str, include=None):
    filtered = []
    for field in row:
        # pylint: disable=superfluous-parens
        if (field or field is 0 or (isinstance(field, float) and field == 0)
                or field in (include or [])):
            filtered.append(field)
        else:
            filtered.append(empty_str)
        # pylint: enable=superfluous-parens
    return filtered
