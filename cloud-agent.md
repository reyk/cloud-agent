CLOUD-AGENT(8) - System Manager's Manual

# NAME

**cloud-agent** - cloud provisioning for OpenBSD VMs

# SYNOPSIS

**cloud-agent**
\[**-nuv**]
\[**-p**&nbsp;*length*]
\[**-r**&nbsp;*rootdisk*]
\[**-t**&nbsp;*timeout*]
\[**-U**&nbsp;*username*]
*interface*

# DESCRIPTION

The
**cloud-agent**
program manages the OpenBSD provisioning and VM interaction in cloud
environments, including Microsoft Azure and Amazon AWS.

The options are as follows:

**-p** *length*

> Generate and set a random password for the default user.
> The password will be written in its plain form into the
> *~/.ssh/authorized\_keys*
> file.
> This allows to use the
> doas(1)
> command to gain root privileges.
> The minimum
> *length*
> is 8 characters and the default is an empty password.

**-n**

> Do not configure the system and skip the provisioning step.

**-t** *timeout*

> Change the HTTP timeout.
> The default is 3 seconds.

**-U** *username*

> Change the default user.
> The default is
> "ec2-user"
> on AWS,
> "azure-user"
> on Azure, and
> "puffy"
> everywhere else.
> The default user is used when it is not obtained from the cloud
> configuration.
> Using
> "root"
> is supported, but not recommended.

**-r** *rootdisk*

> Automatically grow the last
> OpenBSD
> FFS partition of the root disk to use all the available space.

**-u**

> Deprovision and unconfigure the system.
> This deletes keys, passwords, and logs files without asking for permission.

**-v**

> Produce more verbose output.

Enable
**cloud-agent**
in the
hostname.if(5)
of the VM's primary networking interface and automatically the last
partition of the root disk:

	# cat /etc/hostname.hvn0
	dhcp
	!/usr/local/libexec/cloud-agent -r sd0 "\$if"

# FILES

*~/.ssh/authorized\_keys*

> The location of the agent-configured SSH public keys and optional password.

*/usr/local/libexec/cloud-agent*

> The agent itself.

*/usr/local/bin/cms*

> The CMS binary that is used to decrypt messages from the Azure fabric.

*/var/db/cloud-instance*

> The instance ID as reported by the cloud.
> **cloud-agent**
> reprovisions the system when the value has changed.

# SEE ALSO

meta-data(8),
vmd(8)

# AUTHORS

Reyk Floeter &lt;[reyk@openbsd.org](mailto:reyk@openbsd.org)&gt;

OpenBSD 6.5 - June 5, 2019
