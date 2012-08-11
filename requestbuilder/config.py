# Copyright (c) 2012, Eucalyptus Systems, Inc.
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

import ConfigParser
import itertools

class Config(object):
    def __init__(self, filenames, log=None):
        if log:
            self.log = log.getChild('config')
        else:
            self.log = _FakeLogger()
        self.regions = {}
        self.users   = {}
        self.globals = {}
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

    def get_user_option(self, regionspec, option):
        user   = None
        region = None
        if regionspec:
            if '@' in regionspec:
                user, region = regionspec.split('@', 1)
            else:
                region = regionspec
        if not user and region:
            user = self._lookup_recursively(self.regions, region,
                                            'default-user')
        if not user and self.globals.get('default-user'):
            user = self.globals['default-user']
        if not user:
            self.log.debug('no user to find')
            return None
        return self._lookup_recursively(self.users, user, option,
                                        redact=['secret-key'])

    def get_user_option_bool(self, regionspec, option, default=None):
        value = self.get_user_option(regionspec, option)
        if value is None:
            return default
        elif value.lower() in ('true', '1', 'yes', 'on'):
            return True
        elif value.lower() in ('false', '0', 'no', 'off'):
            return False
        else:
            raise ValueError('value {0} is not boolean'.format(repr(value)))

    def get_region_option(self, regionspec, option):
        if regionspec:
            if '@' in regionspec:
                region = regionspec.split('@', 1)[1]
            else:
                region = regionspec
        elif self.globals.get('default-region'):
            region = self.globals['default-region']
        else:
            self.log.debug('no region to find')
            return None
        return self._lookup_recursively(self.regions, region, option)

    def get_region_option_bool(self, regionspec, option, default=None):
        value = self.get_region_option(regionspec, option)
        if value is None:
            return default
        elif value.lower() in ('true', '1', 'yes', 'on'):
            return True
        elif value.lower() in ('false', '0', 'no', 'off'):
            return False
        else:
            raise ValueError('value {0} is not boolean'.format(repr(value)))

    def _lookup_recursively(self, confdict, section, option, redact=None,
                            cont_reason=None):
        ## TODO:  detect loops
        self._memo.setdefault(id(confdict), {})
        if (section, option) in self._memo[id(confdict)]:
            return self._memo[id(confdict)][(section, option)]
        def memoize(value):
            self._memo[id(confdict)][(section, option)] = value
            return value

        section_bits = section.split(':')
        if not cont_reason:
            self.log.debug('searching for option %s', repr(option))
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
                    if redact and option in redact:
                        print_value = '<redacted>'
                    else:
                        print_value = repr(value)
                    self.log.info('option value %s = %s', repr(option),
                                  print_value)
                    return memoize(value)
                elif confdict[prd_section].get('defer-to') in confdict:
                    deferral = confdict[prd_section]['defer-to']
                    return memoize(self._lookup_recursively(
                            confdict, deferral, option,
                            cont_reason='deferred'))
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
                    return memoize(self._lookup_recursively(
                            confdict, matches[0], option,
                            cont_reason=('from ' + repr(section))))
                elif len(matches) > 1:
                    raise ValueError(
                            '{0} is ambiguous; closest matches are {1}'.format(
                            repr(section), ', '.join(map(repr, matches))))
        self.log.info('option value %s not found', repr(option))
        return memoize(None)


class _FakeLogger(object):
    def fake_method(self, *args, **kwargs):
        pass

    def __getattribute__(self, name):
        return object.__getattribute__(self, 'fake_method')
