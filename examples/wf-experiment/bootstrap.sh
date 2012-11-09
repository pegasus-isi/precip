#!/bin/bash

# This script bootstraps a basic RHEL6 instance to be have working
# Condor and Pegasus installs. The script takes one optional
# argument which is the address of the master instance (central
# manager in Condor terminology). If the argument is not given,
# the script sets up the instance to be the master.

MASTER_ADDR=$1

# for images with condor already installed, stop condor
/etc/init.d/condor stop >/dev/null 2>&1 || /bin/true

# correct clock is important for most projects
yum -q -y install ntpdate
/etc/init.d/ntpdate start

# Add the EPEL repository
wget -nv http://mirror.utexas.edu/epel/6/x86_64/epel-release-6-7.noarch.rpm
rpm -Uh epel-release-*.noarch.rpm

# Add the Condor repository
cat >/etc/yum.repos.d/condor.repo <<EOF
[condor-stable]
name=Condor Stable RPM Repository for Redhat Enterprise Linux 6
baseurl=http://www.cs.wisc.edu/condor/yum/stable/rhel6
enabled=1
gpgcheck=0
EOF

# Add the Pegasus repository
cat >/etc/yum.repos.d/pegasus.repo <<EOF
[Pegasus]
name=Pegasus
baseurl=http://download.pegasus.isi.edu/wms/download/rhel/6/x86_64
gpgcheck=0
enabled=1
priority=50
EOF

# Install required software
yum -q -y clean all
yum -q -y install gcc gcc-g++ gcc-gfortran make gawk bison diffutils \
                  java-1.7.0-openjdk.x86_64 \
                  java-1.7.0-openjdk-devel.x86_64 \
                  ganglia-gmond condor pegasus

# Clear the Condor local config file - we use config.d instead
cat /dev/null >/etc/condor/condor_config.local

# Common Condor config between master and workers
cat >/etc/condor/config.d/50-main.conf <<EOF

CONDOR_HOST = $MASTER_ADDR

FILESYSTEM_DOMAIN = \$(FULL_HOSTNAME)
TRUST_UID_DOMAIN = True

DAEMON_LIST = MASTER, STARTD

# security
ALLOW_WRITE = 10.*
ALLOW_READ = \$(ALLOW_WRITE)

# default policy
START = True
SUSPEND = False
CONTINUE = True
PREEMPT = False
KILL = False

EOF

# Master gets extra packages/configs
if [ "x$MASTER_ADDR" = "x" ]; then
    yum -q -y install ganglia-gmetad ganglia-web

    cat >/etc/condor/config.d/90-master.conf <<EOF
CONDOR_HOST = \$(FULL_HOSTNAME)
DAEMON_LIST = MASTER, COLLECTOR, NEGOTIATOR, SCHEDD
EOF
fi

# Restarting daemons
/etc/init.d/condor start

# User to run the workflows as, and allow the experiment management
# ssh key to authenticate
adduser wf
mkdir -p ~wf/.ssh
cp ~/.ssh/authorized_keys ~wf/.ssh/
chown -R wf: ~wf/.ssh
    
# Master is the submit host, so deploy our workflow on it
if [ "x$MASTER_ADDR" = "x" ]; then
    # install the workflow tarball and wait script
    cd ~wf
    wget -q http://pegasus.isi.edu/static/precip/wf-experiment/montage.tar.gz
    tar xzf montage.tar.gz
    chown -R wf: montage*
fi

