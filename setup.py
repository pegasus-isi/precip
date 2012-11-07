import os
from distutils.core import setup

# Utility function to read the README file.
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "peccolo",
    version = "0.1",
    author = "Mats Rynge",
    author_email = "rynge@isi.edu",
    description = ("Pegasus Experiment Cloud Controller - a simple module for running experiments in the cloud"),
    long_description=read('README'),
    license = "Apache2",
    url = "http://pegasus.isi.edu/peccolo",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "License :: OSI Approved :: Apache Software License",
    ],
    packages=["peccolo"],
    package_data={"peccolo": ["resources/vm-bootstrap.sh"]}
)