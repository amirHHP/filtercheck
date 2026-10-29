#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""تست بخش‌های خالص netutil و تشخیص CDN، بدون شبکه."""

import struct
import threading
import time
import unittest

import netutil
from censorship_probe import both_on_known_cdn
from qos_metrics import bytes_to_mbps


class DnsPacketTests(unittest.TestCase):
    def test_parse_a_record_with_name_pointer(self):
        tid, query = netutil.build_dns_query("example.com")
        header = struct.pack(">HHHHHH", tid, 0x8180, 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes((1, 2, 3, 4))
        packet = header + query[12:] + answer
        self.assertEqual(netutil.parse_dns_a(packet, tid), ["1.2.3.4"])

    def test_reject_mismatched_id(self):
        tid, query = netutil.build_dns_query("example.com")
        header = struct.pack(">HHHHHH", tid, 0x8180, 1, 0, 0, 0)
        self.assertEqual(netutil.parse_dns_a(header + query[12:], tid ^ 0x00FF), [])

    def test_nxdomain_is_empty(self):
        tid, query = netutil.build_dns_query("missing.example")
        header = struct.pack(">HHHHHH", tid, 0x8183, 1, 0, 0, 0)
        self.assertEqual(netutil.parse_dns_a(header + query[12:], tid), [])

    def test_query_contains_labels(self):
        _, query = netutil.build_dns_query("example.com")
        self.assertIn(b"\x07example\x03com\x00", query)


class HttpStatusTests(unittest.TestCase):
    def test_success_and_auth_errors_are_reachable(self):
        for code in (200, 204, 301, 302, 401, 403, 429):
            ok, _status = netutil.classify_http_status(code)
            self.assertTrue(ok, code)

    def test_server_error_is_not_reachable(self):
        ok, status = netutil.classify_http_status(500)
        self.assertFalse(ok)
        self.assertIn("500", status)


class CdnPrefixTests(unittest.TestCase):
    def test_specific_cloudflare_and_google_prefixes_match(self):
        self.assertTrue(both_on_known_cdn(["104.21.5.198"], ["172.67.1.1"]))
        self.assertTrue(both_on_known_cdn(["142.250.1.1"], ["216.58.1.1"]))

    def test_broad_prefixes_are_not_treated_as_cdn(self):
        self.assertFalse(both_on_known_cdn(["2.2.2.2"], ["23.1.1.1"]))
        self.assertFalse(both_on_known_cdn(["104.1.1.1"], ["52.1.1.1"]))
        self.assertFalse(both_on_known_cdn(["8.8.8.8"], ["1.1.1.1"]))


class CacheTests(unittest.TestCase):
    def setUp(self):
        netutil.clear_caches()

    def test_singleflight_runs_function_once(self):
        calls = []
        gate = threading.Event()

        def work():
            calls.append(1)
            gate.wait(1)
            return "ok"

        def run():
            return netutil.cached_call("shared-key", work)

        gate.set()
        # Hold the leader inside the function so the others join the same flight.
        gate.clear()
        leader_started = threading.Event()

        def leader():
            def blocked():
                calls.append(1)
                leader_started.set()
                gate.wait(1)
                return "ok"
            return netutil.cached_call("shared-key", blocked)

        threads = [threading.Thread(target=leader)]
        results = []

        def follower():
            results.append(netutil.cached_call("shared-key", work))

        threads[0].start()
        self.assertTrue(leader_started.wait(1))
        others = [threading.Thread(target=follower) for _ in range(6)]
        for thread in others:
            thread.start()
        time.sleep(0.05)
        gate.set()
        threads[0].join(1)
        for thread in others:
            thread.join(1)
        self.assertEqual(calls, [1])
        self.assertEqual(results, ["ok"] * 6)

    def test_clear_caches_forces_a_new_call(self):
        calls = []

        def work():
            calls.append(1)
            return 1

        netutil.cached_call("once", work)
        netutil.cached_call("once", work)
        netutil.clear_caches()
        netutil.cached_call("once", work)
        self.assertEqual(calls, [1, 1])


class SpeedMathTests(unittest.TestCase):
    def test_two_megabytes_in_one_second_is_16_megabits(self):
        self.assertEqual(bytes_to_mbps(2 * 1024 * 1024, 1), 16.78)

    def test_zero_duration_is_zero(self):
        self.assertEqual(bytes_to_mbps(1000, 0), 0.0)


if __name__ == "__main__":
    unittest.main()
