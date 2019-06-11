# Changelog

## v0.9 (unreleased)

* Added support for `-c` to specify the probing order of different cloud stacks.
* Added support for OpenNebula's START_SCRIPT methods (user-data alike).
* Added support for generating a default user password and writing it into
  `~/.ssh/authorized_keys`.
* Fixed handling of OpenNebula SSH_PUBLIC_KEY entries with multiple keys.
* Improved documentation, added `CHANGELOG.md` file.

## v0.8 (2019-06-02)

* Added support for growing the root disk and its last partition (optional).
* Fixed OpenStack support.
* Fixed compilation with LibreSSL on OpenBSD 6.5 or newer.
* Fixed probing order and OpenStack with `169.254.169.254` as the endpoint IP.
* Improved OpenNebula support.

## v0.7 (2018-08-15)

* Added initial support for OpenNebula contextualization.
* Added support for setting a custom login user or "root" with `-U`.
* Added support for writing `resolv.conf` and static network configuration.
* Fixed the generated pf rule that is loaded during cloud-agent operation.

## v0.6 (2018-05-15)

* Fixed compilation with (old) OpenSSL releases.

---

## v0.5 (2018-05-08)

* Fixed the user-data script by loading it from /etc/rc.user-data.

## v0.4 (2018-05-08)

* Added support for user-data that is not base64-encoded.

## v0.3 (2018-05-08)

* Added support for user-data scripts.
* Make the public key optional for stacks that supply a password (e.g. Azure).

## v0.2.2 (2018-05-07)

* Fixed issues in the v0.2.1 release.

## v0.2.2 (2018-05-07)

* Fixed issues in the v0.2 release.

## v0.2 (2018-01-10)

* Added support for OpenStack and its JSON-based meta data.
* Added support for Apache CloudStack.
* Try to get meta data from `dhcp-server-identifier` instead of
  `169.254.169.254`.

## v0.1 (2017-07-03)

* Initial release with support for Microsoft Azure and Amazon AWS EC2.
