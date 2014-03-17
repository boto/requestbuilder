# Copyright (c) 2013-2014, Eucalyptus Systems, Inc.
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
import warnings


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
    # pylint: disable-msg=E1101
    for m_class in cls.mro():
        # pylint: enable-msg=E1101
        if field_name in vars(m_class):
            values.extend(getattr(m_class, field_name))
    return values


def set_userregion(config, userregion, overwrite=False):
    msg = ('set_userregion is deprecated; use '
           'RegionConfigurableMixin.update_config_view instead')
    config.log.warn(msg)
    warnings.warn(msg, DeprecationWarning)
    if userregion is None:
        return
    if '@' in userregion:
        user, region = userregion.split('@', 1)
    else:
        user = None
        region = userregion
    if user and (config.user is None or overwrite):
        config.user = user
    if region and (config.region is None or overwrite):
        config.region = region
    return user, region
