# Copyright (c) 2013-2015, Eucalyptus Systems, Inc.
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

import requestbuilder


def add_default_routes(arglike_obj, default_routes):
    if isinstance(arglike_obj, requestbuilder.Arg):
        if arglike_obj.routes is None:
            arglike_obj.routes = default_routes
    elif isinstance(arglike_obj, list):
        # Note that MutuallyExclusiveArgList is a list
        for item in arglike_obj:
            add_default_routes(item, default_routes)


def aggregate_subclass_fields(cls, field_name):
    values = []
    # pylint doesn't know about classes' built-in mro() method
    # pylint: disable=E1101
    for m_class in cls.mro():
        # pylint: enable=E1101
        if field_name in vars(m_class):
            values.extend(getattr(m_class, field_name))
    return values
