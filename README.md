cloud-agent for OpenBSD
=======================

This is a simple OpenBSD-specific agent that aims to handle
provisioning and cloud initialization on public clouds such as
Microsoft Azure and Amazon AWS.  For OpenBSD on Azure, it is a minimal
alternative to the [WALinuxAgent](https://github.com/Azure/WALinuxAgent/).

Prerequisites
-------------

* OpenBSD 6.1 or higher, nothing else.

Files
-----

* `/usr/local/libexec/cloud-agent`
* `/usr/local/bin/cms`

The CMS binary is a port of OpenSSL's CMS tool to LibreSSL.  LibreSSL
has removed CMS which is required by Azure.

Usage
-----

See the [cloud-agent(8)](cloud-agent.md) documentation for more
information about the usage.

Basic installation is easy, `cloud-agent` detects the cloud type
automatically.

* On Microsoft Azure, create a file `/etc/hostname.hvn0`

* On Amazon AWS, create a file `/etc/hostname.xnf0`

* On CloudStack, such as Exoscale, create a file `/etc/hostname.vio0`

* On OpenBSD VMM (with meta-data), create a file `/etc/hostname.vio0`

* On OpenStack/VMware, create a file `/etc/hostname.vmx0`

* The content of the file is identical for all of the above:

		dhcp
		!/usr/local/libexec/cloud-agent "\$if"

* On OpenNebula, such as Data Center Light, create a file `/etc/hostname.if`
  where _if_ is the name of your primary interface.
  The `dhcp` line should be ommitted in the file:

		!/usr/local/libexec/cloud-agent "\$if"

Releases
--------

See the [Changelog](CHANGELOG.md) for a summary of changes and
download the releases from the
[release page](https://github.com/reyk/cloud-agent/releases).

Author
------

[Reyk Floeter](https://github.com/reyk/).

See the [License](LICENSE.md) file for more information.
