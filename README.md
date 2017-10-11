# backup2swift

[![Build Status](https://travis-ci.org/uq-eresearch/backup2swift.svg?branch=master)](https://travis-ci.org/uq-eresearch/backup2swift)
[![Latest Release](https://img.shields.io/github/release/uq-eresearch/backup2swift.svg)](https://github.com/uq-eresearch/backup2swift/releases/latest)

Backup utility which uses [OpenStack Swift][swift]'s [form post middleware][form_middleware] to perform one-way file backups to object storage without privileged user credentials.

## Usage

Using the form POST middleware for the first time normally requires multiple account configuration steps. `backup2swift` attempts to automate this as much as possible. To create the form template used for backups:

```
source ./MyProject-openrc.sh
backup2swift setup my_backup_container > config.json
```

Then, after copying config.json to the system that needs to perform file backups:

```
backup2swift -c config.json --delete-after 2592000 monday-backup-files.tar.gz monday-backup-db.sql.xz
```

## Static binary

While you can build `backup2swift` for each system you want to use, often a static x86_64 binary is much more useful. The version included with tagged releases is built using [clux/muslrust][muslrust].

### OpenSSL & Certificates

As [noted by the musltrust README](https://github.com/clux/muslrust#ssl-verification), HTTPS support is compiled into the static binary, but the trusted certificate store location may vary between systems. If it is not where `backup2swift` expects, then its HTTPS requests will fail.

These two environment variables can be set in order to specify the trusted certificate store location:

```
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
export SSL_CERT_DIR=/etc/ssl/certs
```

[OpenSSL's documentation](https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_set_default_verify_paths.html) has more details on how to use these variables.


[swift]: http://swift.openstack.org/
[form_middleware]: https://docs.openstack.org/swift/latest/api/form_post_middleware.html
[muslrust]: https://github.com/clux/muslrust
