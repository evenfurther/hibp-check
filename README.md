# Check your Keepass database against HIBP

[Have I been pwned (HIBP)](https://haveibeenpwned.com/) is a service
which tracks leaks of personal data. It records the various breaches and stores
the associated password.

If you use [KeePass](https://keepass.info/) or compatible programs such as
the excellent [KeePassXC](https://keepassxc.org/) for Linux, you might want to
check which of your passwords are weak. A password is weak if it has been
revealed in previous breaches, as dictionary attacks will probably include it.

## Installation

You can compile `hibp-check` by running the `cargo` utility:

```bash
$ cargo build --release
```

You can then install the executable on your system by running:

```bash
$ sudo install -c -m 755 target/release/hibp-check /usr/local/bin
```

## Running `hibp-check`

If your KeePass database is located in `~/keepass/passwords.kdbx`, you can run
`hibp-check` the following ways:

### If you have installed `hibp-check` on your system

```bash
$ hibp-check keepass --ask-password ~/keepass/passwords.kdbx
```

### If you haven't yet installed `hibp-check` on your system

```bash
$ cargo run --release -- keepass --ask-password ~/keepass/passwords.kdbx
```

### Password and key file variation

If you don't use a password, you can omit the `--ask-password` option. If you use a key file
(possibly in addition to a password), add `--key-file FILE` to the command line.

You may also prefer to indicate your password on the command line using `--password PASSWORD`,
but this is not recommended as anyone logged onto the same machine will be able to snoop
your password using the `ps` Unix command.

Also, if you want the compromised passwords to appeared in plain text on the console,
you can add the `--show-password` before `keepass` on the command line.
