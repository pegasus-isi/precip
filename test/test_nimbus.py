#!/usr/bin/python

import unittest
import os
import sys
import time
import traceback

from precip import *


class TestNimbus(unittest.TestCase):

    def setUp(self):
        pass

    def test_nimbus(self):
        result = False
        exp = None
        try:
            exp = NimbusExperiment(
                    os.environ['NIMBUS_URL'],
                    os.environ['NIMBUS_ACCESS_KEY'],
                    os.environ['NIMBUS_SECRET_KEY'])
            exp.provision("centos-5.7-x64.gz", tags=["test1"], count=1)
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

