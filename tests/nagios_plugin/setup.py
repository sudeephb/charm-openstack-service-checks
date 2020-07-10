from setuptools import setup
from tempfile import TemporaryDirectory
import os
import urllib.request


with TemporaryDirectory() as tempd:
    URL = 'https://git.launchpad.net/nrpe-charm/plain/files/nagios_plugin3.py'
    script = os.path.join(tempd, os.path.basename(URL))
    with open(script, 'wb') as dest_f:
        print("downloading {}".format(URL))
        dest_f.write(urllib.request.urlopen(URL).read())
        print("writing {}".format(script))
    setup(
        name='nagios_plugin3',
        description='nagios plugin from the NRPE charm',
        download_url=URL,
        project_urls={
            'nrpe source': 'https://git.launchpad.net/nrpe-charm/',
            'nrpe issues': 'https://bugs.launchpad.net/charm-nrpe',
        },
        classifiers=[
            'Environment :: Plugins',
            'Intended Audience :: Developers',
            'Intended Audience :: System Administrators',
            'Operating System :: POSIX',
            'Programming Language :: Python :: 2.7',
            'Programming Language :: Python :: 3.4',
            'Programming Language :: Python :: 3.5',
            'Programming Language :: Python :: 3.6',
            'Programming Language :: Python :: 3.7',
            'Topic :: Software Development :: Libraries :: Python Modules',
            'Topic :: System :: Monitoring',
        ],
        keywords='nrpe nagios plugin check monitoring',
        author='Llama Charmers',
        author_email='llama-charmers@lists.ubuntu.com ',
        package_dir={'': tempd},
        packages=['']
    )
