"""Copyright 2022 Cado Security Ltd. All rights reserved

Tests for rip_raw

python3 -m unittest tests.DetectExtractMemoryTests
"""
import logging
import os
from typing import Any
import unittest
import zipfile

import rip_raw

class DetectExtractMemoryTests(unittest.TestCase):

    def setUp(self) -> None:
        logging.info('Called detect setUp')
        self.data_dir = './tests/data/'

    def test_detect_extract_memory(self):

        test_file = os.path.join(self.data_dir, 'tiny.mem')
        logging.info(f"Calling test file with {test_file}")

        zip_output = rip_raw.convert_memory_to_zip(test_file)
        zip = zipfile.ZipFile(zip_output)
        expected_zip_contents = ['carved_memory_module_1.bin', 'carved_memory_module_2_37.log', 'carved_memory_module_2.bin']

        zip_contents = zip.namelist()

        for content in expected_zip_contents:
            self.assertIn(content, zip_contents)
        

