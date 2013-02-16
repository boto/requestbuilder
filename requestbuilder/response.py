# Copyright (c) 2013, Eucalyptus Systems, Inc.
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


class PaginatedResponse(dict):
    def __init__(self, request, pages, item_names):
        assert len(pages) > 0
        self.iter_cache = dict((key, []) for key in item_names)
        self.request    = request
        self.stack      = list(reversed(pages))
        self.fetch_next_page()  # get an initial response
        for key in self.iter_cache:
            self[key] = ResponseItemGenerator(key, self)

    def fetch_next_page(self):
        if len(self.stack) == 0:
            raise StopIteration()
        page = self.stack.pop()
        self.request.prepare_for_page(page)
        response = self.request.send()
        next_page = self.request.get_next_page(response)
        for key in self.iter_cache:
            self.iter_cache[key].extend(response.pop(key, []) or [])
        if next_page is not None:
            # Need to ask for another page of results later
            self.stack.append(next_page)
        self.update(response)


class ResponseItemGenerator(object):
    def __init__(self, item_name, response_dict):
        self.item_name     = item_name
        self.response_dict = response_dict

    def next(self):
        if len(self.response_dict.iter_cache[self.item_name]) == 0:
            self.response_dict.fetch_next_page()
        if len(self.response_dict.iter_cache[self.item_name]) == 0:
            raise StopIteration()
        return self.response_dict.iter_cache[self.item_name].pop(0)

    def __iter__(self):
        return self
