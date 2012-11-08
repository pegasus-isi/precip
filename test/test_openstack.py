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

    def test_openstack(self):
        result = False
        exp = None
        try:
            exp = OpenStackExperiment(
                    os.environ['OPENSTACK_URL'],
                    os.environ['OPENSTACK_ACCESS_KEY'],
                    os.environ['OPENSTACK_SECRET_KEY'])
            exp.provision("ami-0000004c", tags=["test1"], count=1)
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

