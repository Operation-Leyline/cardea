"""Regenerate the disposable-domain blocklist the signup trigger compiles in.

`crates/cardea-core/src/disposable_domains.txt` is checked in so signup makes no network
call (crates/cardea-core/src/disposable.rs). This script, run by an operator, replaces it
from the public disposable-email-domains list (CC0) and leaves the diff for
review: a person reads it, then commits. It never runs at signup or in CI.

    python -m tools.refresh_disposable_domains            # fetch, rewrite the file
    python -m tools.refresh_disposable_domains --check    # fetch, exit 1 if the file is out of date
    python -m tools.refresh_disposable_domains --source list.conf   # a local copy, no network

It refuses a list that would break signup rather than writing it: fewer than
`MINIMUM` domains (a truncated download), any of the big mail providers (a
poisoned or mangled source), a line that is not a domain, or a list that drops
more than a third of what the file has now (`--allow-shrink` to accept it).
"""
import argparse
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'crates' / 'cardea-core' / 'src' / 'disposable_domains.txt'
UPSTREAM = ('https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/'
            'main/disposable_email_blocklist.conf')
MINIMUM = 500
MAX_BYTES = 8 * 1024 * 1024
MAX_SHRINK = 1 / 3
# Blocking one of these locks real people out of signup: refuse the list instead.
NEVER_BLOCK = frozenset({
    'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com',
    'icloud.com', 'me.com', 'mac.com', 'proton.me', 'protonmail.com', 'pm.me', 'aol.com', 'fastmail.com',
    'zoho.com', 'gmx.com', 'gmx.net', 'mail.com', 'yandex.com', 'qq.com', '163.com', '126.com',
})
HEADER = (
    '# Disposable and throwaway mail domains refused at signup (crates/cardea-core/src/disposable.rs).\n'
    '# Checked in so signup makes no network call. Refresh: python -m tools.refresh_disposable_domains\n'
    '# Sorted, lowercase, one domain per line; a listed domain also covers its subdomains.\n'
)
DOMAIN = re.compile(r'^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$')


def entries(text):
    """The domains in a list: one per line, `#` comments and blank lines ignored."""
    return [line.strip().lower() for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')]


def parse(text):
    """A sorted set of valid domains, or ValueError naming what is wrong with the list."""
    domains = set()
    for entry in entries(text):
        if not DOMAIN.fullmatch(entry):
            raise ValueError(f'not a domain: {entry!r}')
        domains.add(entry)
    return sorted(domains)


def render(domains):
    return HEADER + ''.join(f'{domain}\n' for domain in domains)


def refreshed(source_text, current_text, allow_shrink=False):
    """The file's new content from the upstream list, or ValueError when it must not replace the current one."""
    domains = parse(source_text)
    if len(domains) < MINIMUM:
        raise ValueError(f'only {len(domains)} domains: the list looks truncated (minimum {MINIMUM})')
    protected = sorted(NEVER_BLOCK.intersection(domains))
    if protected:
        raise ValueError(f'the list blocks mail providers {protected}; refusing it')
    current = set(entries(current_text))
    dropped = current - set(domains)
    if current and not allow_shrink and len(dropped) > len(current) * MAX_SHRINK:
        raise ValueError(f'the list drops {len(dropped)} of {len(current)} current domains; '
                         'check the source, then pass --allow-shrink')
    return render(domains)


def fetch(url=UPSTREAM, opener=urllib.request.urlopen):
    if not url.startswith('https://'):
        raise ValueError('the source must be https')
    with opener(url, timeout=30) as response:
        body = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError('the list is larger than expected; refusing it')
    return body.decode('utf-8')


def run(args, fetcher=fetch, output=OUTPUT):
    """Write (or with `--check`, compare) the file; returns the process exit code."""
    source = Path(args.source).read_text(encoding='utf-8') if args.source else fetcher()
    current = output.read_text(encoding='utf-8') if output.exists() else ''
    updated = refreshed(source, current, args.allow_shrink)
    if updated == current:
        print(f'{output.name} is up to date ({len(entries(updated))} domains)')
        return 0
    if args.check:
        print(f'{output.name} is out of date; run tools/refresh_disposable_domains.py', file=sys.stderr)
        return 1
    output.write_text(updated, encoding='utf-8', newline='\n')
    print(f'wrote {len(entries(updated))} domains to {output.name} (was {len(entries(current))}); review the diff')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--check', action='store_true', help='exit 1 instead of writing when the file is out of date')
    parser.add_argument('--source', help='read this file instead of fetching the public list')
    parser.add_argument('--allow-shrink', action='store_true', help='accept a list that drops many current domains')
    try:
        return run(parser.parse_args(argv))
    except ValueError as error:
        print(f'refused: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
