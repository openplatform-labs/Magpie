"""Check the built shell is compatible with the TLS proxy's script CSP."""
from html.parser import HTMLParser
from pathlib import Path


class ShellParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inline_scripts = 0
        self.stylesheets = []
        self.inline_handlers = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == 'script' and not values.get('src'):
            self.inline_scripts += 1
        if tag == 'link' and values.get('rel') == 'stylesheet':
            self.stylesheets.append(values)
        self.inline_handlers.extend(name for name, _ in attrs if name.startswith('on'))


parser = ShellParser()
parser.feed(Path('dist/magpie/browser/index.html').read_text())
assert parser.inline_scripts == 0, 'Inline script would be blocked by script-src self'
assert not parser.inline_handlers, 'Inline event handlers would be blocked by CSP'
assert any(link.get('media', 'all') == 'all' for link in parser.stylesheets), 'Main styles must load without inline scripts'
print('Built shell contains no CSP-blocked script or event handlers.')
