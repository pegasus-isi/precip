#!/usr/bin/python

import os
import time

from peccolo import *

ec2 = None
fg = None

try:

    # This example show how to run an experiment between Amazon EC2
    # and an OpenStack resource on FutureGrid. The setup is pretty
    # similar to the HelloWorld example, except that we now have to
    # experiment to handle. The first step is to get the experiments
    # initialized. Note that it is not required to use environment
    # variables for your credentials, but seperating the crenditals
    # from the code prevents the credentials from being check in to
    # source control systems.
    
    ec2 = EC2Experiment(
            "us-west-2c",
            "ec2.us-west-2.amazonaws.com",
            os.environ['AMAZON_EC2_ACCESS_KEY'],
            os.environ['AMAZON_EC2_SECRET_KEY'])
   
    fg = OpenStackExperiment(
            os.environ['EC2_URL'],
            os.environ['EC2_ACCESS_KEY'],
            os.environ['EC2_SECRET_KEY'])

    # Next we provision two instances, one on Amazon EC2 and one of
    # FutureGrid
    ec2.provision("ami-8a1e92ba", tags=["id=ec2_1"])
    fg.provision("ami-0000004c", tags=["id=fg_1"])

    # Wait for all instances to boot and become accessible. The provision
    # method only starts the provisioning, and can be used to start a large
    # number of instances at the same time. The wait method provides a 
    # barrier to when it is safe to start the actual experiment.
    ec2.wait([])
    fg.wait([])
    
    # Run commands on the remote instances
    ec2.run([], "echo 'Hello world Amazon EC2'")
    fg.run([], "echo 'Hello world FutureGrid OpenStack'")

except ExperimentException as e:
    # This is the default exception for most errors in the api
    print "ERROR: %s" % e
    raise e
finally:
    # Be sure to always deprovision the instances we have started. Putting
    # the deprovision call under finally: make the deprovisioning happening
    # even in the case of failure.
    if ec2 is not None:
        ec2.deprovision([])
    if fg is not None:
        fg.deprovision([])

