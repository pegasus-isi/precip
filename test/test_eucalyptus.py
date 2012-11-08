#!/usr/bin/python

import unittest
import os
import sys
import time
import traceback

from precip import *


class TestEucalyptus(unittest.TestCase):

    def setUp(self):
        pass

    def test_eucalyptus(self):
        result = False
        exp = None
        try:
            exp = EucalyptusExperiment(
                    os.environ['EUCALYPTUS_URL'],
                    os.environ['EUCALYPTUS_ACCESS_KEY'],
                    os.environ['EUCALYPTUS_SECRET_KEY'])
            exp.provision("emi-77373D4C", tags=["test1"], count=1)
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

