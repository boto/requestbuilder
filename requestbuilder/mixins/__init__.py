# Copyright (c) 2012-2015, Eucalyptus Systems, Inc.
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

import os

from requestbuilder import Arg


class RegionConfigurableMixin(object):
    """
    A mixin that allows the user to specify which user/region names to use
    for the configuration via a --region arg and, if a 'REGION_ENVVAR' class
    variable is set, an environment variable as well.  The included
    update_config_view method actually reads these data and updates
    self.config to point to them.
    """

    ARGS = [Arg('--region', metavar='USER@REGION', route_to=None,
                help=('region and/or user names to search when looking up '
                      'config file data'))]

    def update_config_view(self, region=None, user=None):
        # Different sources of user/region info can override only parts of
        # the set, so we only overwite things conditionally.

        # self.args gets highest precedence
        if self.args.get('region'):
            _user, _region = self.__parse_region(self.args['region'])
            user = user or _user
            region = region or _region
        # Environment comes next
        if (getattr(self, 'REGION_ENVVAR', None) and
                os.getenv(self.REGION_ENVVAR)):
            _user, _region = self.__parse_region(os.getenv(self.REGION_ENVVAR))
            user = user or _user
            region = region or _region
        # Default region from the config file
        if not region:
            region = self.config.get_global_option('default-region')
        # User info can come from a region, so set that in the config now.
        if region:
            self.config.region = region
        # Look up the region's user if needed...
        if not user:
            user = self.config.get_region_option('user')
        # ...and finally update the config with that as well.
        if user:
            self.config.user = user

    @staticmethod
    def __parse_region(regionish):
        """
        Given a string with pattern "[USER@][REGION]", return the user
        and region names that that string represents, if any, and None
        for the values it does not represent.

        Examples:
         - ""          -> (None, None)
         - "spam"      -> (None, "spam")
         - "eggs@"     -> ("eggs", None)
         - "eggs@spam" -> ("eggs", "spam")
        """

        if not regionish:
            return None, None
        if regionish.endswith('@'):
            return regionish.rstrip('@'), None
        elif '@' in regionish:
            return regionish.split('@', 1)
        else:
            return None, regionish


# Compatibility with requestbuilder < 0.3
from .formatting import TabifyingMixin
from .progress import FileTransferProgressBarMixin
