"""Speed regressions in a scanner are correctness regressions in practice:
a first run that takes ninety seconds on one file is a first run nobody
finishes. These pin the two fixes that took a 39MB transcript from 89s to 2s.
"""
import time
import unittest

from ranwhat import clean


class Linear(unittest.TestCase):
    def test_origin_scan_does_not_go_quadratic_on_prose(self):
        """_ORIGIN rescans forward from every position on long word runs. 16k
        characters used to cost 1.7s; the literal prefilter makes it free."""
        text = "a" * 50000
        t = time.perf_counter()
        clean._origins(text)
        self.assertLess(time.perf_counter() - t, 0.05)

    def test_origins_still_found_when_a_marker_is_present(self):
        self.assertIn("~/.ssh/id_rsa", clean._origins("then cat ~/.ssh/id_rsa here"))
        self.assertIn("api/.env", clean._origins("read api/.env"))

    def test_origins_skip_templates(self):
        self.assertEqual(clean._origins("cp .env.example .env.example"), [])


class EmbeddedImages(unittest.TestCase):
    PNG = "iVBORw0KGgoAAAANSUhEUgAA" + "A" * 300000

    def test_embedded_png_is_not_scanned(self):
        t = time.perf_counter()
        self.assertEqual(clean.find_secrets(self.PNG), [])
        self.assertLess(time.perf_counter() - t, 0.05)

    def test_image_data_cannot_produce_a_false_positive(self):
        """Random-looking base64 can contain an AKIA-shaped run by chance."""
        planted = "iVBORw0KGgo" + "Q" * 5000 + "AKIAIOSFODNN7EXAMPLE" + "Q" * 5000
        self.assertEqual(clean.find_secrets(planted), [])

    def test_short_text_starting_like_an_image_is_still_scanned(self):
        """Only long whitespace-free blobs count as images."""
        text = "Qk AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY9"
        self.assertTrue(clean.find_secrets(text))

    def test_real_secret_in_ordinary_text_still_found(self):
        text = "export STRIPE_KEY=sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc" + " and done"
        labels = [label for _, label in clean.find_secrets(text)]
        self.assertTrue(labels, "a live-shaped key in prose was missed")


if __name__ == "__main__":
    unittest.main()
