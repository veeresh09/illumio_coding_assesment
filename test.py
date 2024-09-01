import unittest
import tempfile
import os
from processLogs import read_lookup_table, process_flow_logs

class TestNetworkFunctions(unittest.TestCase):
    
    def test_read_lookup_table(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            test_data = """dstport,proto,tag
80,tcp,HTTP
443,tcp,HTTPS
53,udp,DNS
"""
            temp_file.write(test_data)
            temp_file_name = temp_file.name

        try:
            lookup_table, err = read_lookup_table(temp_file_name)
            self.assertIsNone(err)

            expected = {
                80: {"tcp": "http"},
                443: {"tcp": "https"},
                53: {"udp": "dns"},
            }

            self.assertEqual(lookup_table, expected)
        finally:
            os.remove(temp_file_name)

    def test_process_flow_logs(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            test_data = """version acc_id interface-id 192.168.1.1 10.0.0.1 1234 80 6
version acc_id interface-id 192.168.1.2 10.0.0.2 5678 443 6
version acc_id interface-id 192.168.1.3 10.0.0.3 9012 53 17
version acc_id interface-id 192.168.1.4 10.0.0.4 3456 8080 6"""
            temp_file.write(test_data)
            temp_file_name = temp_file.name

        try:
            lookup_table = {
                80: {"tcp": "HTTP"},
                443: {"tcp": "HTTPS"},
                53: {"udp": "DNS"},
                8080: {"tcp": "HTTP-ALT"},
            }

            tag_counts, port_and_protocol_counts, err = process_flow_logs(temp_file_name, lookup_table)
            self.assertIsNone(err)

            expected_tag_counts = {
                "HTTP": 1,
                "HTTPS": 1,
                "DNS": 1,
                "HTTP-ALT": 1,
            }

            expected_port_and_protocol_counts = {
                80: {"tcp": 1},
                443: {"tcp": 1},
                53: {"udp": 1},
                8080: {"tcp": 1},
            }

            self.assertEqual(tag_counts, expected_tag_counts)
            self.assertEqual(port_and_protocol_counts, expected_port_and_protocol_counts)
        finally:
            os.remove(temp_file_name)

    def test_empty_lookup_table(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            test_data = """version acc_id interface-id 192.168.1.1 10.0.0.1 80 1234 6"""
            temp_file.write(test_data)
            temp_file_name = temp_file.name

        try:
            lookup_table = {}

            tag_counts, port_and_protocol_counts, err = process_flow_logs(temp_file_name, lookup_table)
            self.assertIsNone(err)

            expected_tag_counts = {"Untagged": 1}
            expected_port_and_protocol_counts = {1234: {"tcp": 1}}

            self.assertEqual(tag_counts, expected_tag_counts)
            self.assertEqual(port_and_protocol_counts, expected_port_and_protocol_counts)
        finally:
            os.remove(temp_file_name)

    def test_invalid_data_format(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            test_data = """version acc_id interface-id 192.168.1.1 10.0.0.1 5 1234 unknown_protocol
version acc_id interface-id 192.168.1.2 10.0.0.2 443 invalidport 6"""
            temp_file.write(test_data)
            temp_file_name = temp_file.name

        try:
            lookup_table = {
                80: {"tcp": "HTTP"},
                443: {"tcp": "HTTPS"},
                53: {"udp": "DNS"},
                8080: {"tcp": "HTTP-ALT"},
            }

            tag_counts, port_and_protocol_counts, err = process_flow_logs(temp_file_name, lookup_table)
            self.assertIsNone(err)

            expected_tag_counts = {"Untagged": 1}
            expected_port_and_protocol_counts = {1234: {"unknown": 1}}

            self.assertEqual(tag_counts, expected_tag_counts)
            self.assertEqual(port_and_protocol_counts, expected_port_and_protocol_counts)
        finally:
            os.remove(temp_file_name)

if __name__ == '__main__':
    unittest.main()