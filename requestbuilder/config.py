# Copyright (c) 2012-2013, Eucalyptus Systems, Inc.
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

from __future__ import absolute_import

import ConfigParser
import itertools
import logging

class Config(object):
    def __init__(self, filenames, loglevel=None):
        self.log = logging.getLogger(self.__class__.__name__)
        if loglevel is not None:
            self.log.level = loglevel
        self.globals = {}
        self.regions = {}
        self.users   = {}
        self.__current_region = None
        self.__current_user   = None
        self._memo   = {}
        self._parse_config(filenames)

    def _parse_config(self, filenames):
        parser = ConfigParser.SafeConfigParser()
        parser.read(filenames)
        for section in parser.sections():
            if section == 'global':
                self.globals = dict(parser.items(section))
            elif section.startswith('region '):
                region = section.split()[1]
                if any(chunk == '' for chunk in region.split(':')):
                    raise ValueError(('configuration file region {0} must not '
                                      'contain an empty namespace').format(
                                     repr(region)))
                if '@' in region:
                    raise ValueError(('configuration file region {0} must not '
                                      'contain @ characters').format(
                                     repr(region)))
                self.regions[region] = dict(parser.items(section))
                self.regions[region].setdefault('name', region.rsplit(':')[-1])
            elif section.startswith('user '):
                user = section.split()[1]
                if any(chunk == '' for chunk in user.split(':')):
                    raise ValueError(('configuration file user {0} must not '
                                      'contain an empty namespace').format(
                                     repr(user)))
                if '@' in user:
                    raise ValueError(('configuration file user {0} must not '
                                      'contain @ characters').format(
                                     repr(user)))
                self.users[user] = dict(parser.items(section))
            # Ignore unrecognized sections for forward compatibility

    @property
    def current_region(self):
        # This is a property so we can log when it is set.
        return self.__current_region

    @current_region.setter
    def current_region(self, val):
        self.log.debug('current region set to %s', repr(val))
        self.__current_region = val

    def get_region(self):
        if self.current_region is not None:
            return self.current_region
        if 'default-region' in self.globals:
            return self.globals['default-region']
        return None

    @property
    def current_user(self):
        # This is a property so we can log when it is set.
        return self.__current_user

    @current_user.setter
    def current_user(self, val):
        self.log.debug('current user set to %s', repr(val))
        self.__current_user = val

    def get_user(self):
        if self.current_user is not None:
            return self.current_user
        if self.get_region() is not None:
            # Try to pull it from the current region
            region_user = self.get_region_option('user')
            if region_user is not None:
                return region_user
        if 'default-user' in self.globals:
            return self.globals['default-user']
        return None

    def get_global_option(self, option):
        return self.globals.get(option)

    def get_global_option_bool(self, option, default=None):
        value = self.get_global_option(option)
        return convert_to_bool(value, default=default)

    def get_user_option(self, option, user=None, redact=False):
        if user is None:
            user = self.get_user()
        if user is None:
            return None
        return self._lookup_recursively('users', self.users, user, option,
                                        redact=redact)

    def get_user_option_bool(self, option, user=None, default=None):
        value = self.get_user_option(option, user=user)
        return convert_to_bool(value, default=default)

    def get_region_option(self, option, region=None, redact=False):
        if region is None:
            region = self.get_region()
        if region is None:
            return None
        return self._lookup_recursively('regions', self.regions, region,
                                        option, redact=redact)

    def get_region_option_bool(self, option, region=None, default=None):
        value = self.get_region_option(option, region=region)
        return convert_to_bool(value, default=default)

    def _lookup_recursively(self, confdict_name, confdict, section, option,
                            redact=None, cont_reason=None):
        # TODO:  detect loops
        self._memo.setdefault(id(confdict), {})
        if (section, option) in self._memo[id(confdict)]:
            return self._memo[id(confdict)][(section, option)]
        def memoize(value):
            self._memo[id(confdict)][(section, option)] = value
            return value

        section_bits = section.split(':')
        if not cont_reason:
            self.log.debug('searching %s for option %s', confdict_name,
                           repr(option))
        for prd in itertools.product((True, False), repeat=len(section_bits)):
            prd_section = ':'.join(section_bits[i] if prd[i] else '*'
                                   for i in range(len(section_bits)))
            if cont_reason:
                self.log.debug('  section %s (%s)', repr(prd_section),
                               cont_reason)
                cont_reason = None
            else:
                self.log.debug('  section %s', repr(prd_section))
            if prd_section in confdict:
                if option in confdict[prd_section]:
                    value = confdict[prd_section][option]
                    # Check if we're supposed to pull from another section
                    if value.startswith('use '):
                        value_chunks = value.split()
                        if len(value_chunks) == 1:
                            raise ValueError("something must follow 'use' in "
                                             "{0}".format(repr(value)))
                        new_section = value_chunks[1]
                        if len(value_chunks) > 2:
                            new_option = value_chunks[2]
                        else:
                            new_option = option
                        return memoize(self._lookup_recursively(confdict_name,
                                confdict, new_section, new_option,
                                cont_reason='deferred'))
                    # We're done!
                    if redact:
                        print_value = '<redacted>'
                    else:
                        print_value = repr(value)
                    self.log.info('option %s = %s', repr(option), print_value)
                    return memoize(value)
        # That didn't work; try matching something higher in the hierarchy.
        # Example:  'us-east-1' -> 'aws:us-east-1'
        c_counts = {}
        for match in [m_section for m_section in confdict
                      if m_section.endswith(section)]:
            count = match.count(':') + 1
            c_counts.setdefault(count, [])
            c_counts[count].append(match)
        for count in sorted(c_counts.keys()):
            if count > len(section_bits):
                matches = c_counts[count]
                if len(matches) == 1:
                    return memoize(self._lookup_recursively(confdict_name,
                            confdict, matches[0], option,
                            cont_reason=('from ' + repr(section))))
                elif len(matches) > 1:
                    raise ValueError(
                            '{0} is ambiguous; closest matches are {1}'.format(
                            repr(section), ', '.join(map(repr, matches))))
        self.log.info('option %s not found', repr(option))
        return memoize(None)


def convert_to_bool(value, default=None):
    if value is None:
        return default
    elif value.lower() in ('true', '1', 'yes', 'on'):
        return True
    elif value.lower() in ('false', '0', 'no', 'off'):
        return False
    else:
        raise ValueError('value {0} is not boolean'.format(repr(value)))
