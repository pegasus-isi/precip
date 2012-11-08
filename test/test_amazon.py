#!/usr/bin/python

import unittest
import os
import sys
import time
import traceback

from precip import *


class TestOpenStack(unittest.TestCase):

    def setUp(self):
        pass

    def test_amazon(self):
        result = False
        exp = None
        try:
            exp = EC2Experiment(
                    "us-west-2c",
                    "ec2.us-west-2.amazonaws.com",
                    os.environ['AMAZON_EC2_ACCESS_KEY'],
                    os.environ['AMAZON_EC2_SECRET_KEY'])
            exp.provision("ami-8a1e92ba", tags=["test1"], count=1)
            exp.wait()
            exp.run(["test1"], "echo 'Hello world from a experiment instance'")
            result = True
        except Exception as e:
            print "ERROR: %s" % e
            traceback.print_exc(file=sys.stdout)
        finally:
            if exp is not None:
                exp.deprovision()
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()

