#!/usr/bin/python

import os
import time

from precip import *

try:

    # This experiment is targeted to run on OpenStack
    exp = OpenStackExperiment(
            os.environ['OPENSTACK_URL'],
            os.environ['OPENSTACK_ACCESS_KEY'],
            os.environ['OPENSTACK_SECRET_KEY'])

    # We need a master Condor node and a set of workers
    exp.provision("ami-0000004c", tags=["master"],
                  instance_type="m1.large")
    exp.provision("ami-0000004c", tags=["compute"],
                  instance_type="m1.large", count=2)
    exp.wait()

    # The workers need to know what the private hostname of the master is
    master_priv_addr = exp.get_private_hostnames(["master"])[0]

    # Bootstrap the instances. This includes installing Condor and Pegasus,
    # downloading and settup the workflow.
    exp.copy_and_run(["master"], "./bootstrap.sh")
    exp.copy_and_run(["compute"], "./bootstrap.sh", args=[master_priv_addr])

    # Give the workers some time to register with the Condor central 
    # manager
    time.sleep(60)

    # Make sure Condor came up correctly
    exp.run(["master"], "condor_status")

    # Run the workflow
    exp.run(["master"], "cd ~/montage && ./run-montage", user="wf")

    # At this point, in a real experiment, you could for example provision
    # more resources and run the workflow again, or run the workflow with
    # different parameters/settings.

except ExperimentException as e:
    print "ERROR: %s" % e
finally:
    # always want to clean up all the instances we have started
    exp.deprovision([])

