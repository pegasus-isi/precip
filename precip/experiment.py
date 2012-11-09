"""

Copyright 2012 University Of Southern California

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0
                                                                                                                             
Unless required by applicable law or agreed to in writing,                                                                 
software distributed under the License is distributed on an "AS IS" BASIS,                                                 
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.                                                   
See the License for the specific language governing permissions and                                                        
limitations under the License. 

"""

import logging
import os
import random
import re
import socket
import subprocess
import time

import paramiko

import boto
from boto.ec2.connection import EC2Connection
from boto.ec2.regioninfo import *
from boto.exception import EC2ResponseError

__all__ = ["ExperimentException",
           "EC2Experiment",
           "NimbusExperiment",
           "EucalyptusExperiment",
           "OpenStackExperiment"]

logging.basicConfig(level=logging.WARN)

logger = logging.getLogger('precip')
logger.setLevel(level=logging.INFO)

boto_logger = logging.getLogger('boto')
boto_logger.setLevel(level=logging.FATAL)


class SSHConnection:
    """ 
    Helper class for simple ssh functionality such as copying files and running commands.
    
    The only authentication method supported is ssh pub/priv key authentication.
    """
    
    def _new_connection(self, privkey, host, user):
        """
        Internal method for setting up a ssh connection. As the instances come up with different
        host keys all the time, the host key validation has been disabled.
        
        :return: a handle to the ssh connection
        """ 
        ssh = paramiko.SSHClient()
        hkeys = ssh.get_host_keys()
        hkeys.clear()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=user, key_filename=privkey, allow_agent=False, look_for_keys=False )
        return ssh
    
    def run(self, privkey, host, user, cmd):
        """
        Runs a command on the remote machine.
        
        :return: exit code, stdout and stderr from the command
        """
        logger.debug("Running command on host %s as user %s: %s" % (host, user, cmd))
        out = ""
        err = ""
        ssh = self._new_connection(privkey, host, user)
        chan = ssh.get_transport().open_session()
        stdin = chan.makefile("wb", -1)
        stdout = chan.makefile("rb", -1)
        stderr = chan.makefile_stderr("rb", -1)
        chan.exec_command(cmd)
        stdin.flush()
        exit_code = chan.recv_exit_status()
        for line in stdout:
            out += line
        for line in stderr:
            err += line
        ssh.close()        
        return exit_code, out, err

    def put(self, privkey, host, user, local_path, remote_path):
        """
        Copies file from the local machine to the remote machine
        """
        ssh = self._new_connection(privkey, host, user)
        ftp = ssh.open_sftp()
        ftp.put(local_path, remote_path)
        ftp.close()
        ssh.close()

    def get(self, privkey, host, user, remote_path, local_path):
        """
        Copies file from the remote machine to the local machine
        """
        ssh = self._new_connection(privkey, host, user)
        ftp = ssh.open_sftp()
        ftp.get(remote_path, local_path)
        ftp.close()
        ssh.close()


class ExperimentException(Exception):
    """
    Class for grouping the most common experiment failures 
    """
    pass


class Instance:
    """
    Representation of an instance, and a few common attributes of that instance
    """
    
    id = None
    priv_addr = None
    pub_addr = None
    tags = []
    ec2_instance = None
    is_fully_instanciated = False
    
    def __init__(self, instance_id):
        """
        :param instance_id: a unique identifier for the instance, for example the amazon instance id
        """
        self.id = instance_id
        self.tags = []
    
    def add_tag(self, tag):
        """
        Tagging is implemented in our own instance as some infrastructures (OpenStack, ...) have not implemented
        tagging in their API
        """
        self.tags.append(tag)
        
    def has_tags(self, tags):
        """
        Checks if the instance have all the tags queried for
        """
        try:
            for t in tags:
                # if the tag does not exists, we fail here with a ValueException
                self.tags.index(t)
        except ValueError:
            return False            
        return True
    
    def info(self):
        i = {}
        i["id"] = self.id
        i["public_address"]  = self.pub_addr
        i["private_address"] = self.priv_addr
        i["tags"] = self.tags
        return i


class Experiment:
    """
    Base class for all types of cloud implementations. This is what defines the experiment API.
    """
    
    def __init__(self):
        """
        Constructor for a new experiment - this will set up ~/.precip and ssh keys if they
        do not already exist
        """
        
        self._instances = []
        
        self._conf_dir = os.path.join(os.environ["HOME"], ".precip")
        
        # checking/creating conf directory
        if not os.path.exists(self._conf_dir):
            os.makedirs(self._conf_dir)
        
        # ssh keys setup 
        self._ssh_pubkey = os.path.join(self._conf_dir, "id_rsa.pub")
        self._ssh_privkey = os.path.join(self._conf_dir, "id_rsa")
        if not os.path.exists(self._ssh_privkey):
            logger.info("Creating new ssh key in " + self._conf_dir)
            cmd = "ssh-keygen -q -t rsa -f " + self._ssh_privkey + " </dev/null"
            p = subprocess.Popen(cmd, shell=True)
            stdoutdata, stderrdata = p.communicate()
            rc = p.returncode
            if rc != 0:
                raise ExperimentException("Command '%s' failed with error code %s" % (cmd, rc))

    def _instance_subset(self, tags):
        """
        Returns the subset of instances matching the tags
        """
        subset = []
        for i in self._instances:
            if i.has_tags(tags):
                subset.append(i)
        return subset
    
    def _is_valid_hostaddr(self, addr):
        """
        Checks if a host address is "external". Note that addr can be either an ip address
        or a fqdn.
        """
        
        re_ip = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        r = re_ip.search(self._endpoint)
        if not r:
            # assume addr is a fqdn
            try:
                addr = socket.gethostbyname(addr)
            except socket.gaierror:
                # unable to dns look up addr
                return False

        # at this point addr should be in ip format
        
        # private up addresses are not valid (there is probably a better way to check this)
        if addr[:3] == "10." or addr[:4] == "192." or addr[:4] == "172.":
            return False 
        
        # make sure addr is a valid ip address
        try:
            socket.inet_aton(addr)
            # valid
        except socket.error:
            return False
        return True
        
    def provision(self, image_id, instance_type='m1.small', count=1, tags=None):
        """
        Provision a new instance. Note that this method starts the provisioning cycle, but does not
        block for the instance to finish booting - for that, see wait()
        
        :param image_id: The image id as specified by the cloud infrastructure
        :param instance_type: The instance type (m1.small, m1.large, ...)
        :param count: Number of instances to provision. The default is 1.
        :param tags: Tags to add to the instance - this is important as tags are used throughout the API 
                     to find and manipulate instances
        """                                                                   
        pass
    
    def wait(self, tags=[], timeput=600):
        """
        Barrier for all currently instances to finish booting and be accessible via external addresses.
        
        :param tags: set of tags to match against
        :param timeout: maximum timeout to wait for instances to come up
        """
        return True

    def list(self, tags=[]):
        """
        Provides a list of instances, and instance details, with the matching tags
        
        :param tags: set of tags to match against
        :return: list of instance descriptions
        """
        l = []
        for i in self._instance_subset(tags):
            l.append(i.info())
        return l
        
    def deprovision(self, tags=[]):
        """
        Deprovisions (terminates) instances with the matching tags
        
        :param tags: set of tags to match against
        """
        pass
    
    def get_public_hostnames(self, tags=[]):
        """
        Get the set of public hostnames (or IP addresses) for instances matching 'tags'
        
        :param tags: set of tags to match against
        """
        addresses = []
        for i in self._instance_subset(tags):
            addresses.append(i.pub_addr)
        return addresses

    def get_private_hostnames(self, tags=[]):
        """
        Get the set of private hostnames (or IP addresses) for instances matching 'tags'
        
        :param tags: set of tags to match against
        """
        addresses = []
        for i in self._instance_subset(tags):
            addresses.append(i.priv_addr)
        return addresses
    
    def get(self, tags, remote_path, local_path, user="root"):
        """
        Transfers a file from a set of remote machines matching the tags, and stores the file locally.
        If more than one instance matches the tags, an instance id will be appended to the local_path. 
        
        :param tags: set of tags to match against
        :param remote_path: location of the file on the remote instance
        :param local_path: local location for where to store the file
        """
        ssh = SSHConnection()
        iset = self._instance_subset(tags)
        
        # if the instance set is larger than one, enable the appending of 
        # instance id to the local path
        append_instance_id = True
        if len(iset) == 1:
            append_instance_id = False
            
        for i in self._instance_subset(tags):
            modified_local_path = local_path
            if append_instance_id:
                modified_local_path = local_path + "." + i.id
            # should we do checks on the target path? Directory check? Existing file check?
            ssh.get(self._ssh_privkey, i.pub_addr, user, remote_path, modified_local_path)

    def put(self, tags, local_path, remote_path, user="root"):
        """
        Transfers a local file to a set of instances matching the given tags
        
        :param tags: set of tags to match against
        :param local_path: local location for the source file
        :param remote_path: location of where to copy the file to
        :param user: user to transfer as, default is 'root'
        """
        ssh = SSHConnection()
        for i in self._instance_subset(tags):
            ssh.put(self._ssh_privkey, i.pub_addr, user, local_path, remote_path)
    
    def run(self, tags, cmd, user="root", check_exit_code=True):
        """
        Runs a command on set of instances matching the tags given.
        
        :param tags: set of tags to match against
        :param cmd: command to run
        :param user: the user to run the command as
        """
        exit_code_list = []
        out_list = []
        err_list = []
        ssh = SSHConnection()
        for i in self._instance_subset(tags):
            logger.info("Scheduling command execution on %s: %s" % (i.id, cmd))
            exit_code = -1
            out = ""
            err = ""
            try:
                exit_code, out, err = ssh.run(self._ssh_privkey, i.pub_addr, user, cmd)
            except Exception, e:
                raise ExperimentException("Error running ssh command", e)
            if len(out) > 0:
                logger.info("  stdout: %s" % out)
            if len(err) > 0:
                logger.info("  stderr: %s" % err)
            
            exit_code_list.append(exit_code)
            out_list.append(out)
            err_list.append(err)
                
            if check_exit_code and exit_code != 0:
                raise ExperimentException("Command exited with exit code %d" % exit_code)
        
        return exit_code_list, out_list, err_list
                
    def copy_and_run(self, tags, local_script, args=[], user="root", check_exit_code=True):
        """
        Runs a local script on the remote instances matching the tags
        
        :param tags: set of tags to match against
        :param local_script: local script to copy and run
        :param args: list of arguments to pass to the script
        :param user: user to run the script as
        """
        fname = "/tmp/remote-exec.%d" % (random.randint(1, 10000000000)) 
        self.put(tags, local_script, fname, user=user)
        cmd = "cd /tmp && chmod 755 %s && %s" % (fname, fname)
        for a in args:
            cmd = cmd + " '" + a + "'"
        cmd = cmd + " && rm -f " + fname
        exit_codes, outs, errs = self.run(tags, cmd, user=user, check_exit_code=check_exit_code)
        return exit_codes, outs, errs



class EC2Experiment(Experiment):
     
    def __init__(self, region, endpoint, access_key, secret_key):
        """
        Initializes an EC2 experiment
        
        :param region: Amazon EC2 region, for example us-west-2c
        :param endpoint: Amazon EC2 endpoint, for example ec2.us-west-2.amazonaws.com
        :param access_keys: Amazon EC2 access key
        :param secret_keys: Amazon EC2 secret key
        """        
        Experiment.__init__(self)
    
        self._region = region
        self._endpoint = endpoint
        self._access_key = access_key
        self._secret_key = secret_key
    
        self._conn = None
        
        # some infrastructures do not support security groups
        self._security_groups_support = True
    
        self._get_connection()
        self._ssh_keys_setup()
        self._security_groups_setup()

    def _get_connection(self):
        """
        Establishes a connection to the cloud endpoint
        """
        if (self._conn != None):
            return
                                                                                                                    
        logger.info("Connecting to endpoint " + self._endpoint)
        
        re_endpoint = re.compile(r'(([\w]+)://)?([\w\.\-]*)(?::(\d+))?(/[\S]*)?')
        r = re_endpoint.search(self._endpoint)
        if not r:
            raise ExperimentException("Unable to parse endpoint: %s" % (self._endpoint))

        # Parse successfu
        proto = r.group(2)
        host = r.group(3)
        port = r.group(4)
        path = r.group(5)
        
        if proto is None:
            proto = "http"
        
        if port is None:
            if proto == "http":
                port = 80
            else:
                port = 443
        else:
            port = int(port)
            
        if path is None:
            path = ""
            
        is_secure=(proto == "https")
        # Nimbus wants is_secure to be true
        if self._region == "nimbus":
            is_secure = True
                                                                                  
        region = RegionInfo(name=self._region, endpoint=host)   
                                                
        self._conn = boto.connect_ec2(
                        self._access_key,
                        self._secret_key,
                        is_secure=is_secure,
                        region=region,
                        port=port,
                        path=path)
    
        # this next line is due to a bug in early boto versions
        self._conn.host = host
    
        # do a query to validate that the connection works
        try:
            self._conn.get_all_instances()
        except EC2ResponseError, e:
            self.ec2_conn = None
            raise ExperimentException("Unable to talk to the service", e)
             
    def _ssh_keys_setup(self):
        """
        Makes sure we have our experiment keypair registered
        """
        keypairs = None
        try:
            keypairs = self._conn.get_key_pair("precip")
            # TODO: verify that the the existing keypair matches the one in ~/.precip
        except IndexError, ie:
            # not found on eucalyptus
            pass
        except EC2ResponseError, e:
            if e.error_code in ["InvalidKeyPair.NotFound", "EC2APIError"]:
                keypairs = None
            else:
                raise ExperimentException("Unable to query for key pair", e)
            
        if keypairs is None:
            logger.info("Registering ssh pubkey as 'precip'")
            f = open(self._ssh_pubkey)
            contents = f.read()
            f.close()
            self._conn.import_key_pair("precip", contents)
                  
    def _security_groups_setup(self):
        """
        Sets up the default security group
        """
        sgroups = None
        try:
            sgroups = self._conn.get_all_security_groups(["precip"])
        except EC2ResponseError, e:
            if e.error_code in ["InvalidGroup.NotFound", "SecurityGroupNotFoundForProject"]:
                sgroups = None
            else:
                raise ExperimentException("Unable to find security group", e)
        
        if sgroups is None:
            try:
                logger.info("Registering default security group 'precip'")
                sg = self._conn.create_security_group("precip", "FutureGrid Experiment Mangement default group")
                sg.authorize(ip_protocol='tcp', from_port=22, to_port=22, cidr_ip='0.0.0.0/0')
                sg.authorize(src_group=sg)
            except Exception:
                logger.warn("Security group seems to be broken - disabling support")
                self._security_groups_support = False
                pass
    
    def _finish_instanciation(self, instance):
        """
        Finishes booting and bootstraps an instace
        
        :param instance: the instance to check
        :return: True if the instance is ready, otherwise False
        """
        # check if we are already done
        if instance.is_fully_instanciated:
            return True
            
        # now, let's wait until the instance i up and running        
        ec2inst = instance.ec2_instance
        ec2inst.update()
        
        if ec2inst.state != "pending" and ec2inst.state != "running":
            raise ExperimentException("Unexpected instance state for instance %s: %s" % (instance.id, ec2inst.state))
        
        if ec2inst.state == "pending":
            logger.debug("Instance %s is still pending" % instance.id)
            return False
    
        if not self._is_valid_hostaddr(ec2inst.public_dns_name):
            logger.debug("Waiting for instance %s to boot and be assigned a public IP address" % instance.id)
            return False
        
        # fill out instance fields
        instance.priv_addr = ec2inst.private_dns_name
        instance.pub_addr = ec2inst.public_dns_name
            
        # bootstrap the image
        exit_code = -1
        out = ""
        err = ""
        try:
            ssh = SSHConnection()
            script_path = os.path.dirname(os.path.abspath(__file__)) + "/resources/vm-bootstrap.sh"
            ssh.put(self._ssh_privkey, ec2inst.public_dns_name, "root", script_path, "/root/vm-bootstrap.sh")
            exit_code, out, err = ssh.run(self._ssh_privkey, ec2inst.public_dns_name, "root", "chmod 755 /root/vm-bootstrap.sh && /root/vm-bootstrap.sh")
        except paramiko.SSHException:
            logger.debug("Failed to run bootstrap script on instance %s. Will retry later." % instance.id)
            return False
        except socket.error:
            logger.debug("Unable to ssh connect to instance %s. Will retry later." % instance.id)
            return False
        
        if len(out) > 0:
            logger.info("  stdout: %s" % out)
        if len(err) > 0:
            logger.info("  stderr: %s" % err)
        if exit_code != 0:
            raise ExperimentException("Bootstrap script exited with error %d" % exit_code)
        
        logger.info("Instance %s has booted, public hostname: %s" % (instance.id, ec2inst.public_dns_name))
        
        instance.add_tag(instance.pub_addr)
        instance.is_fully_instanciated = True
        return True
            
    def provision(self, image_id, instance_type='m1.small', count=1, tags=None):                                                                   
        """
        Provision a new instance. Note that this method starts the provisioning cycle, but does not
        block for the instance to finish booting - for that, see wait()
        
        :param image_id: The image id as specified by the cloud infrastructure
        :param instance_type: The instance type (m1.small, m1.large, ...)
        :param count: Number of instances to provision. The default is 1.
        :param tags: Tags to add to the instance - this is important as tags are used throughout the API 
                     to find and manipulate instances
        """   
        
        self._get_connection()
               
        for i in range(count):
            try:
                # create a boto image object from the image id
                image_obj = self._conn.get_image(image_id)

                if self._security_groups_support:
                    res = image_obj.run(instance_type=instance_type, key_name="precip", security_groups=["precip"])
                else:
                    res = image_obj.run(instance_type=instance_type, key_name="precip")
                logger.info("Started instance %s, type %s" % (res.instances[0].id, instance_type))        
            except Exception as e:
                raise ExperimentException("Unable to provision a new instance", e)
        
            instance = Instance(res.instances[0].id)
            instance.ec2_instance = res.instances[0]
            
            # add basic tags
            instance.add_tag("precip")
            instance.add_tag(instance.id)
            for t in tags:
                instance.add_tag(t)
            
            self._instances.append(instance)
        
    def wait(self, tags=[], timeout=600):
        """
        Barrier for all currently instances to finish booting and be accessible via external addresses.
        
        :param tags: set of tags to match against
        :param timeout: maximum timeout to wait for instances to come up
        """
        start_time = int(time.time())
        count_pending = -1
        while count_pending != 0:
            count_pending = 0
            for i in self._instance_subset(tags):
                if not self._finish_instanciation(i):
                    count_pending += 1
            if count_pending > 0:
                current_time = int(time.time())
                if start_time + timeout < current_time:
                    raise ExperimentException("Timeout reached while waiting for instances to boot")
                logger.info("Waiting for %d instances to finish booting" % (count_pending))
                time.sleep(60)    
            
    def deprovision(self, tags=[]):
        """
        Deprovisions (terminates) instances with the matching tags
        
        :param tags: set of tags to match against
        """
        self._get_connection()
        for i in self._instance_subset(tags):
            logger.info("Deprovisioning instance: %s" % i.id)
            self._conn.terminate_instances(instance_ids=[i.id])
            self._instances.remove(i)


class OpenStackExperiment(EC2Experiment):
    """
    A class defining an experiment running on top of OpenStack
    """
    
    def __init__(self, endpoint, access_key, secret_key):
        """
        Initializes an OpenStack experiment
        
        :param endpoint: OpenStack endpoint
        :param access_keys: OpenStack access key
        :param secret_keys: OpenStack secret key
        """        
        EC2Experiment.__init__(self, "openstack", endpoint, access_key, secret_key)


class EucalyptusExperiment(EC2Experiment):
    """
    A class defining an experiment running on top of Eucalyptus
    """
    
    def __init__(self, endpoint, access_key, secret_key):
        """
        Initializes an Eucalyptus experiment
        
        :param endpoint: Eucalyptus endpoint
        :param access_keys: Eucalyptus access key
        :param secret_keys: Eucalyptus secret key
        """        
        EC2Experiment.__init__(self, "eucalyptus", endpoint, access_key, secret_key)


class NimbusExperiment(EC2Experiment):
    """
    A class defining an experiment running on top of Nimbus
    """
    
    def __init__(self, endpoint, access_key, secret_key):
        """
        Initializes a Nimbus experiment
        
        :param endpoint: Nimbus endpoint
        :param access_keys: Nimbus access key
        :param secret_keys: Nimbus secret key
        """       
        EC2Experiment.__init__(self, "nimbus", endpoint, access_key, secret_key)
