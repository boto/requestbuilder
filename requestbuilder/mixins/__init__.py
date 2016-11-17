# Copyright (c) 2012-2016 Hewlett Packard Enterprise Development Company LP
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

import six

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
        # If the caller specified something directly we overwrite
        # whatever may be there unconditionally.
        if region:
            self.config.region = region
        if user:
            self.config.user = user

        # Otherwise, different sources of user/region info can override
        # only one of the pair, so we only overwite them individually,
        # and then only when no values are already set.

        # self.args gets highest precedence
        if self.args.get('region'):
            self.__setdefault_view_attrs(
                '--region CLI option "{0}"'.format(self.args['region']),
                *self.__parse_region(self.args['region']))
        # Environment comes next
        region_envvar = getattr(self, 'REGION_ENVVAR', None)
        if isinstance(region_envvar, (list, tuple)):
            for var in region_envvar:
                if os.getenv(var):
                    self.__setdefault_view_attrs(
                        'environment variable "{0}"'.format(var),
                        *self.__parse_region(os.getenv(var)))
                    break
        elif isinstance(region_envvar, six.string_types):
            if os.getenv(region_envvar):
                self.__setdefault_view_attrs(
                    'environment variable "{0}"'.format(region_envvar),
                    *self.__parse_region(os.getenv(region_envvar)))
        # Default region from the config file
        self.__setdefault_view_attrs(
            '"default-region" global config option',
            region=self.config.get_global_option('default-region'))
        # We've gone through all possible means of region selection, so
        # if no user is yet selected look it up in the region's config.
        user, section = self.config.get_region_option2('user')
        self.__setdefault_view_attrs(
            '"user" config option for region "{0}"'.format(section),
            user=user)

    def __setdefault_view_attrs(self, cause, user=None, region=None):
        if region and not self.config.region:
            self.log.info('selected region "%s" from %s', region, cause)
            self.config.region = region
        if user and not self.config.user:
            self.log.info('selected user "%s" from %s', user, cause)
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
