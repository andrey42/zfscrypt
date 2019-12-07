# zfscrypt

zfscrypt implements a [Linux Pluggable Authentication Module](https://github.com/linux-pam/linux-pam) that encrypts users home directories with their login password leveraging [ZFS](https://github.com/zfsonlinux/zfs) native encryption. The concept was heavily inspired by Google's [fscrypt](https://github.com/google/fscrypt).

> **Warning:** This is my first project written in C. It might contain severe security issues.

## Features & Usage

All datasets with the following properties will be automatically unlocked when the corresponding user logs in (and locked after logout).

| Property                           | Value        |
|------------------------------------|--------------|
| `io.github.benkerry:zfscrypt_user` | user name    |
| `encryption`                       | not `off`    |
| `keyformat`                        | `passphrase` |
| `keylocation`                      | `prompt`     |
| `canmount`                         | not `off`    |

### Create a new user with zfscrypt

The encryption key and the login password must be the same, otherwise automatic unlocking won't work. Future password changes will update the encryption key automatically.

~~~ sh
zfs create -o mountpoint=/home tank/home
zfs create -o io.github.benkerry:zfscrypt_user=ben -o encryption=on -o keyformat=passphrase -o keylocation=prompt -o canmount=noauto tank/home/ben
zfs mount tank/home
zfs mount tank/home/ben
useradd --create-home ben
zfs allow -u ben load-key,change-key,mount tank/home/ben 
passwd ben
~~~

### Migrate an existing user to zfscrypt

~~~ sh
mv /home/ben /home/_ben
zfs create -o io.github.benkerry:zfscrypt_user=ben -o encryption=on -o keyformat=passphrase -o keylocation=prompt -o canmount=noauto -o mountpoint=/home/ben tank/home/ben
zfs allow -u ben load-key,change-key,mount tank/home/ben
zfs mount tank/home/ben
chown ben:ben /home/ben
chmod 0700 /home/ben
cp -ar /home/_ben/. /home/ben/
rm -rf /home/_ben
~~~

## Building & Installing

### Build dependencies

zfscrypt has the following build dependencies:

- `gcc` or `clang`
- `make`
- `libpam` headers
- `libzfs` headers
- `libnvpair` headers

Depending on your distribution the libraries might be packaged as `libpam-dev`, `libzfs-devel` or something similar.

### Runtime dependencies

zfscrypt requires ZFS v0.8.0 or later. You can check the version with:

~~~ sh
zfs -V
~~~

Arch Linux and Ubuntu 19.10 or newer are known to meet this requirement.

Additionally following libraries must be present:

- `libpam.so`
- `libzfs.so`
- `libnvpair.so`

This libraries are almost certainly already on your system. As long as you use ZFS at least.

### Setup

First build the PAM module.

~~~ sh
make
~~~

Then install (or update) it.

~~~
sudo make install
~~~

Unfortunately PAM configuration is a bit of a mess, because every distribution configures PAM differently. If you are not using Ubuntu have a look at the Arch Linux section below. Maybe you can adapt it to your distribution.

Having problems with PAM? Maybe the [official documentation](http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_SAG.html) or one of this Arch Wiki pages [pam](https://wiki.archlinux.org/index.php/PAM), [fscrypt](https://wiki.archlinux.org/index.php/Fscrypt) can help you.

#### Ubuntu

Fortunately Ubuntu comes with a mechanism to configure PAM automatically.

~~~ sh
sudo cp ./extras/ubuntu/usr/share/pam-configs/zfscrypt /usr/share/pam-configs/
sudo pam-auth-update --enable zfscrypt
~~~

#### Arch Linux

Append this line to the `auth` section in `/etc/pam.d/system-login`:

~~~ pam
auth optional pam_zfscrypt.so
~~~

And append this two lines to the `session` section:

~~~ pam
session [success=1 default=ignore] pam_succeed_if.so service = systemd-user quiet
session optional pam_zfscrypt.so
~~~

The first line is needed to work around some [quirks in systemd](https://wiki.archlinux.org/index.php/Pam_mount).

ZFS encryption enforces a minimum password length of eight characters. So if you use `pam_unix.so` and/or `pam_cracklib.so` add `minlen=8` to their module arguments in `/etc/pam.d/passwd`. It should look something like this:

~~~ pam
password required pam_unix.so sha512 shadow minlen=8
~~~

Finally append the next line to `etc/pam.d/passwd`:

~~~ pam
password optional pam_zfscrypt.so
~~~

## Configuration

The behaivor of zfscrypt can be altered with the following, optional module arguments:

| Argument      | Description                                                                                                                   |
|---------------|-------------------------------------------------------------------------------------------------------------------------------|
| `runtime_dir` | where to store session counters, defaults to `/run/zfscrypt`                                                                  |
| `free_inodes` | enables freeing of reclaimable inodes and dentries on logout, which might bring security benefits and/or performance problems |
| `debug`       | enables verbose logging                                                                                                       |

Example entry in `/etc/pam.d/system-login`:

~~~ pam
session optional pam_zfscrypt.so runtime_dir=/tmp/zfscrypt free_inodes debug
~~~
