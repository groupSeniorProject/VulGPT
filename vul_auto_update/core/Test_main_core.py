import unittest
from vul_auto_update.core.main_core import extract_cwe, extract_osv, start_auto_update, view_cwe, view_osv, delete_cwe, delete_osv

class TestMainCore(unittest.TestCase):

    def test_extract_cwe(self):
        try:
            extract_cwe()
            self.assertTrue(True)
        except Exception as e:
            self.fail(f"extract_cwe failed: {e}")

    def test_extract_osv(self):
        try:
            extract_osv("example-package", "Maven")
            self.assertTrue(True)
        except Exception as e:
            self.fail(f"extract_osv failed: {e}")

    def test_start_auto_update(self):
        try:
            start_auto_update()
            self.assertTrue(True)
        except Exception as e:
            self.fail(f"start_auto_update failed: {e}")

    def test_view_cwe(self):
        try:
            view_cwe()
            self.assertTrue(True)
        except Exception as e:
            self.fail(f"view_cwe failed: {e}")

    def test_view_osv(self):
        try:
            view_osv()
            self.assertTrue(True)
        except Exception as e:
            self.fail(f"view_osv failed: {e}")


if __name__ == "__main__":
    unittest.main()
