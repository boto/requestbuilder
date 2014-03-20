# Copyright (c) 2012-2014, Eucalyptus Systems, Inc.
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


class ConfigView(object):
    def __init__(self, data, region=None, user=None):
        self.log = data.log
        self.__data = data
        self.region = region
        self.user = user

    def clone(self, region=None, user=None):
        region = region or self.region
        user = user or self.user
        return ConfigView(self.__data, region=region, user=user)

    def get_global_option(self, option, redact=False):
        return self.__data.lookup_global(option, redact=redact)

    def get_region_option(self, option, region=None, redact=False):
        return self.get_region_option2(option, region=region,
                                       redact=redact)[0]

    def get_region_option2(self, option, region=None, redact=False):
        region = region or self.region
        if region:
            return self.__data.lookup(self.__data.regions, region, option,
                                      redact=redact,
                                      confdict_log_name='region')
        return None, None

    def get_user_option(self, option, user=None, redact=False):
        return self.get_user_option2(option, user=user, redact=redact)[0]

    def get_user_option2(self, option, user=None, redact=False):
        user = user or self.user
        if user:
            return self.__data.lookup(self.__data.users, user, option,
                                      redact=redact, confdict_log_name='user')
        return None, None

    def get_all_region_options(self, option):
        return self.__get_all_options(self.__data.regions, option)

    def get_all_user_options(self, option):
        return self.__get_all_options(self.__data.users, option)

    @staticmethod
    def __get_all_options(confdict, option):
        matches = {}
        for section, options in confdict.iteritems():
            if '*' not in section and option in options:
                matches[section] = options[option]
        return matches

    @staticmethod
    def convert_to_bool(value, default=None):
        if value is None:
            return default
        elif str(value).lower() in ('true', '1', 'yes', 'on'):
            return True
        elif str(value).lower() in ('false', '0', 'no', 'off'):
            return False
        else:
            raise ValueError('value {0} is not boolean'.format(repr(value)))


class ConfigData(object):
    def __init__(self, filenames):
        self.log = logging.getLogger('Config')
        self.log.addHandler(_NullLogHandler())  # cheap warning silencing
        self.globals = {}
        self.regions = {}
        self.users = {}
        self._memo = {}
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

    def lookup_global(self, option, redact=False):
        self._memo.setdefault(id(self.globals), {})
        if option in self._memo[id(self.globals)]:
            return self._memo[id(self.globals)][option]
        else:
            self.log.info('finding global option %s', option)
            value = self.globals.get(option)
            self._memo[id(self.globals)][option] = value
            if value:
                self.log.info('  found   %s = %s', option, value)
            else:
                self.log.info('  novalue for %s', option)
            return value

    def lookup(self, confdict, section, option, redact=False, seen=None,
               confdict_log_name=None):
        self._memo.setdefault(id(confdict), {})
        if (section, option) in self._memo[id(confdict)]:
            return self._memo[id(confdict)][(section, option)]
        else:
            if confdict_log_name is not None:
                self.log.info('finding %s option %s', confdict_log_name,option)
            values = self.__lookup(confdict, section, option, redact=redact,
                                   seen=seen)
            self._memo[id(confdict)][(section, option)] = values
            return values

    def __lookup(self, confdict, section, option, redact=False, seen=None):
        def redact_if_necessary(value):
            if redact:
                return '<redacted>'
            else:
                return value

        if seen is None:
            seen = []

        # Try wildcard combinations, from most specific to least specific,
        # except for the '*' section, which we handle later on because it is
        # also the global default.
        section_bits = section.split(':')
        for prd in itertools.product((True, False), repeat=len(section_bits)):
            if prd == (False,):
                continue  # We'll handle '*' later.
            s_section = ':'.join(section_bits[i] if prd[i] else '*'
                                 for i in range(len(section_bits)))
            self.log.debug('  section %s', s_section)
            if s_section in confdict and option in confdict[s_section]:
                value = confdict[s_section][option]
                # Check if we're redirected to another section.
                if value.startswith('use '):
                    value_bits = value.split()
                    if len(value_bits) == 1:
                        raise ValueError("something must follow 'use' in {0}"
                                         .format(value))
                    new_section = value_bits[1]
                    if len(value_bits) > 2:
                        new_option = value_bits[2]
                    else:
                        new_option = option
                    self.log.debug('  jump-to %s::%s (deferred)', new_section,
                                   new_option)
                    if new_section not in seen:
                        return self.lookup(confdict, new_section, new_option,
                                           redact=redact,
                                           seen=(seen + [section]))
                    else:
                        self.log.warning('  aborting jump due to a loop')
                # We're done!
                self.log.info('  found   %s::%s = %s', s_section, option,
                              redact_if_necessary(repr(value)))
                return value, s_section
        # Then see if we can find an exact match with a prefix in front of it.
        # Example:  'us-east-1' -> 'aws:us-east-1'
        prefixed_counts = {}
        for s_section in confdict:
            s_section_bits = s_section.split(':')
            if (len(s_section_bits) > len(section_bits) and
                    s_section_bits[-len(section_bits):] == section_bits):
                # It is longer and its last bits are the same as the entirety
                # of section_bits
                prefixed_counts.setdefault(len(s_section_bits), [])
                prefixed_counts[len(s_section_bits)].append(s_section)
        if prefixed_counts:
            shortest_prefixed = prefixed_counts[min(prefixed_counts)]
            if len(shortest_prefixed) == 1:
                self.log.debug('  jump-to %s::%s (from %s)',
                               shortest_prefixed[0], option, section)
                if shortest_prefixed[0] not in seen:
                    return self.lookup(confdict, shortest_prefixed[0], option,
                                       redact=redact, seen=(seen + [section]))
                else:
                    self.log.warning('  aborting jump due to a loop')
            else:
                raise ValueError(
                    '{0} is ambiguous; closest matches are {1}'.format(
                        repr(section), ', '.join(shortest_prefixed)))
        # Finally, try the global default, '*'.
        self.log.debug('  section *')
        if '*' in confdict and option in confdict['*']:
            self.log.info('  found   *::%s = %s', option,
                          redact_if_necessary(repr(value)))
            return value, '*'
        self.log.info('  novalue for %s', option)
        return None, None


class _NullLogHandler(logging.Handler):
    def handle(self, record):
        pass

    def emit(self, record):
        pass

    def createLock(self):
        self.lock = None
