import argparse
import tempfile
import unittest
from pathlib import Path

import tools.refresh_disposable_domains as refresh


def listing(count, prefix='throwaway'):
    return ''.join(f'{prefix}{i:04d}.example\n' for i in range(count))


def args(**fields):
    return argparse.Namespace(**{'check': False, 'source': None, 'allow_shrink': False, **fields})


class RefreshTests(unittest.TestCase):
    """The fetch is a fake: no test touches the network."""

    def test_a_fresh_list_is_sorted_deduplicated_and_headed(self):
        text = 'B.example\n# comment\n\na.example\nb.example\n' + listing(refresh.MINIMUM)
        out = refresh.refreshed(text, '')
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith('# Disposable'))
        domains = refresh.entries(out)
        self.assertEqual(domains, sorted(set(domains)))
        self.assertEqual(domains.count('b.example'), 1)
        self.assertIn('a.example', domains)

    def test_a_truncated_download_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'truncated'):
            refresh.refreshed(listing(refresh.MINIMUM - 1), '')

    def test_a_list_that_blocks_a_mail_provider_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'gmail.com'):
            refresh.refreshed(listing(refresh.MINIMUM) + 'gmail.com\n', '')

    def test_a_line_that_is_not_a_domain_is_refused(self):
        for bad in ('user@mailinator.com', 'has space.com', 'nodots', 'http://x.com', '-a.com'):
            with self.assertRaises(ValueError, msg=bad):
                refresh.refreshed(listing(refresh.MINIMUM) + bad + '\n', '')

    def test_a_list_that_drops_most_of_the_current_file_needs_a_flag(self):
        current = refresh.render(refresh.parse(listing(refresh.MINIMUM, 'old')))
        replacement = listing(refresh.MINIMUM, 'new')
        with self.assertRaisesRegex(ValueError, '--allow-shrink'):
            refresh.refreshed(replacement, current)
        self.assertIn('new0000.example', refresh.refreshed(replacement, current, allow_shrink=True))

    def test_check_reports_drift_without_writing_and_a_run_writes_then_is_quiet(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'disposable_domains.txt'
            output.write_text(refresh.render(['old.example']), encoding='utf-8')
            extra = Path(directory) / 'extra.txt'
            extra.write_text('# none\n', encoding='utf-8')
            before = output.read_text(encoding='utf-8')
            fake = lambda: listing(refresh.MINIMUM)
            self.assertEqual(refresh.run(args(check=True, allow_shrink=True), fake, output, extra), 1)
            self.assertEqual(output.read_text(encoding='utf-8'), before)
            self.assertEqual(refresh.run(args(allow_shrink=True), fake, output, extra), 0)
            self.assertEqual(len(refresh.entries(output.read_text(encoding='utf-8'))), refresh.MINIMUM)
            self.assertEqual(refresh.run(args(check=True), fake, output, extra), 0)

    def test_a_refresh_keeps_the_extra_domains(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'disposable_domains.txt'
            extra = Path(directory) / 'extra.txt'
            extra.write_text('# ours\nonly-ours.example\nthrowaway0000.example\n', encoding='utf-8')
            self.assertEqual(refresh.run(args(), lambda: listing(refresh.MINIMUM), output, extra), 0)
            domains = refresh.entries(output.read_text(encoding='utf-8'))
            self.assertIn('only-ours.example', domains)
            self.assertEqual(domains.count('throwaway0000.example'), 1)
            self.assertEqual(len(domains), refresh.MINIMUM + 1)

    def test_extra_domains_do_not_hide_a_truncated_download(self):
        with self.assertRaisesRegex(ValueError, 'truncated'):
            refresh.refreshed(listing(refresh.MINIMUM - 1), '', extra_text='a.example\nb.example\n')

    def test_an_extra_entry_is_held_to_the_same_rules(self):
        for bad in ('gmail.com\n', 'not a domain\n'):
            with self.assertRaises(ValueError, msg=bad):
                refresh.refreshed(listing(refresh.MINIMUM), '', extra_text=bad)

    def test_a_missing_extra_list_stops_the_refresh(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'disposable_domains.txt'
            with self.assertRaises(FileNotFoundError):
                refresh.run(args(), lambda: listing(refresh.MINIMUM), output, Path(directory) / 'absent.txt')
            self.assertFalse(output.exists())

    def test_the_fetch_is_https_only_and_size_bounded(self):
        with self.assertRaises(ValueError):
            refresh.fetch('http://example.com/list')

        class Response:
            def __init__(self, size):
                self.size = size

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self, limit):
                return b'a' * min(self.size, limit)

        with self.assertRaisesRegex(ValueError, 'larger'):
            refresh.fetch('https://example.com/list', lambda url, timeout: Response(refresh.MAX_BYTES + 10))
        self.assertEqual(refresh.fetch('https://example.com/list', lambda url, timeout: Response(3)), 'aaa')

    def test_the_checked_in_file_passes_its_own_rules(self):
        text = refresh.OUTPUT.read_text(encoding='utf-8')
        domains = refresh.entries(text)
        self.assertGreaterEqual(len(domains), refresh.MINIMUM)
        self.assertEqual(domains, refresh.parse(text))
        self.assertFalse(refresh.NEVER_BLOCK.intersection(domains))
        self.assertEqual(text, refresh.render(domains))

    def test_the_checked_in_extra_list_is_sorted_and_merged(self):
        extra = refresh.EXTRA.read_text(encoding='utf-8')
        self.assertEqual(refresh.entries(extra), refresh.parse(extra))
        listed = set(refresh.entries(refresh.OUTPUT.read_text(encoding='utf-8')))
        self.assertEqual(set(refresh.entries(extra)) - listed, set())


if __name__ == '__main__':
    unittest.main()
