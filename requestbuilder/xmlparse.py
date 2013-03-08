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

try:
    from xml.etree import cElementTree as ElementTree
except ImportError:
    from xml.etree import ElementTree


def parse_aws_xml(xml_stream, list_item_tags=None):
    '''
    Parse a stream of XML and return a nested dict.  The dict represents each
    XML element with a key that matches the element's name and a value of
    another dict if the element contains at least one child element, or the
    element's text if it does not.

    For each element whose name appears in the list_item_tags list, its dict
    value will instead be a list that aggregates the values of every element
    with that name.

    This function is designed to parse XML from AWS services that include list
    items alongside other elements, such as S3.

    Examples:
        <a><b>spam</b><c>eggs</c></a> -> {'a': {'b': 'spam', 'c': 'eggs'}}

        <a>
          <b>
            <c>spam</c>
          </b>          + ['b'] -> {'a': {'b': [{'c': 'spam'}, {'c': 'eggs'}]}}
          <b>
            <c>eggs</c>
          </b>
        </a>
    '''
    # One fundamental assumption we make here is that elements contain text
    # xor other elements.
    if list_item_tags is None:
        list_item_tags = ()
    stack = [(None, {})]
    try:
        for event, elem in ElementTree.iterparse(xml_stream,
                                                 events=('start', 'end')):
            tag = _strip_tag(elem.tag)
            if event == 'start':
                stack.append((tag, {}))
            if event == 'end':
                if tag in list_item_tags:
                    # We're ending a list item, so append it to stack[-2]'s list
                    stack[-2][1].setdefault(tag, [])
                    if stack[-1][1] == {}:
                        # No inner elements; use text instead
                        stack[-2][1][tag].append(elem.text)
                    else:
                        stack[-2][1][tag].append(stack[-1][1])
                else:
                    if stack[-1][1] == {}:
                        # No inner elements; use text instead
                        stack[-2][1][tag] = elem.text
                    else:
                        stack[-2][1][tag] = stack[-1][1]
                stack.pop()
                elem.clear()  # free up some memory
    except ElementTree.ParseError:
        raise ValueError('XML parse error')
    return stack[0][1]


def parse_listdelimited_aws_xml(xml_stream, list_tags=None):
    '''
    Parse a stream of XML and return a nested dict.  The dict represents each
    XML element with a key that matches the element's name and a value of
    another dict if the element contains at least one child element, or the
    element's text if it does not.

    For each element whose name appears in the list_tags list, its dict
    value will instead be a list that aggregates the values of each of that
    element's children.

    This function is designed to parse XML from AWS services that explicitly
    start and end lists with their own elements, such as EC2.

    Examples:
        <a><b>spam</b><c>eggs</c></a> -> {'a': {'b': 'spam', 'c': 'eggs'}}

        <a>
          <b>
            <c>spam</c>
          </b>          + ['b'] -> {'a': [{'c': 'spam'}, {'c': 'eggs'}]}
          <b>
            <c>eggs</c>
          </b>
        </a>
    '''
    # One fundamental assumption we make here is that elements contain text
    # xor other elements.
    if list_tags is None:
        list_tags = ()
    stack = [(None, {})]
    try:
        for event, elem in ElementTree.iterparse(xml_stream,
                                                 events=('start', 'end')):
            tag = _strip_tag(elem.tag)
            if event == 'start':
                if tag in list_tags:
                    # Start a new list
                    stack.append((tag, []))
                else:
                    stack.append((tag, {}))
            elif event == 'end':
                assert tag == stack[-1][0]
                if isinstance(stack[-2][1], list):
                    # Add the thing we just finished parsing to the list
                    if stack[-1][1] == {}:
                        # No inner elements; use text instead
                        stack[-2][1].append(elem.text)
                    else:
                        stack[-2][1].append(stack[-1][1])
                else:
                    # Add the thing we just finished parsing to the dict
                    if stack[-1][1] == {}:
                        # No inner elements; use text instead
                        stack[-2][1][tag] = elem.text
                    else:
                        stack[-2][1][tag] = stack[-1][1]
                stack.pop()
                elem.clear()  # free up some memory
    except ElementTree.ParseError:
        raise ValueError('XML parse error')
    return stack[0][1]


def _strip_tag(elem_tag):
    if elem_tag.startswith('{'):
        return elem_tag.split('}', 1)[1]
    else:
        return elem_tag
