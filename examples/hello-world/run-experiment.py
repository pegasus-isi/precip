#!/usr/bin/python

import os
import time
from pprint import pprint

from precip import *

exp = None

# Use try/except liberally in your experiments - the api is set up to
# raise ExperimentException on most errors
try:

    # Create a new OpenStack based experiment. In this case we pick
    # up endpoints and access/secret cloud keys from the environment
    # as exposing those is the common setup on FutureGrid
    exp = OpenStackExperiment(
            os.environ['EC2_URL'],
            os.environ['EC2_ACCESS_KEY'],
            os.environ['EC2_SECRET_KEY'])

    # Provision an instance based on the ami-0000004c. Note that tags are
    # used throughout the api to identify and manipulate instances. You 
    # can give an instance an arbitrary number of tags.
    exp.provision("ami-0000004c", tags=["test1"], count=1)

    # Wait for all instances to boot and become accessible. The provision
    # method only starts the provisioning, and can be used to start a large
    # number of instances at the same time. The wait method provides a 
    # barrier to when it is safe to start the actual experiment.
    exp.wait()

    # Print out the details of the instance. The details include instance id,
    # private and public hostnames, and tags both defined by you and some
    # added by the api
    pprint(exp.list())
   
    # Run a command on the instances having the "test1" tag. In this case we
    # only have one instance, but if you had multiple instances with that
    # tag, the command would run on each one.
    exp.run(["test1"], "echo 'Hello world from a experiment instance'")

except ExperimentException as e:
    # This is the default exception for most errors in the api
    print "ERROR: %s" % e

finally:
    # Be sure to always deprovision the instances we have started. Putting
    # the deprovision call under finally: make the deprovisioning happening
    # even in the case of failure.
    if exp is not None:
        exp.deprovision()

