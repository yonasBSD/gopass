# FAQ

## How does gopass relate to HashiCorp vault?

While [Vault](https://www.vaultproject.io/) is for machines, gopass is for humans [#7](https://github.com/gopasspw/gopass/issues/7)

## `gopass show secret` displays `Error: Failed to decrypt`

This issue may happen if your GPG setup is broken. On MacOS try `brew link --overwrite gnupg`. You also may need to set `export GPG_TTY=$(tty)` in your `.bashrc` [#208](https://github.com/gopasspw/gopass/issues/208), [#209](https://github.com/gopasspw/gopass/issues/209)

## `gopass recipients add` fails with `Warning: No matching valid key found`

If the key you're trying to add is already in your keyring you may need to trust it. If this is your key run `gpg --edit-key [KEYID]; trust (set to ultimate); quit`, if this is not your key run `gpg --edit-key [KEYID]; lsign; save; quit`

## How can gopass handle binary data?

gopass is designed not to change the content of the secrets in any way except that it will add a final newline at the end of the secret if it does not have one already and the output is going to a terminal. This means that the output may mess up your terminal if it's not only text. In this case you should either encode the secret to text (e.g. base64) before inserting or use the special `gopass binary` sub-command that does that for you.

## Why does gopass delete my whole KDE klipper history?

KDEs klipper provides a clipboard history for your convenience. Since we currently can't figure out which entry may contain a secret copied to the clipboard, we just clear the whole history once the clipboard timer expires.

## Can I use gopass as an token helper for Vault?

Yes, there is [a repo](https://github.com/frntn/vault-token-helper-gopass) that provides the necessary scripts and instructions.

## Does gopass support re-encryption? 

Adding or removing recipients with `gopass recipients add` or `gopass recipients remove` will automatically re-encrypt all affected secrets. Further, `gopass fsck` checks for missing recipients and reencrypts the secret if necessary.

## gopass can automatically import missing recipient keys, but can it export them as well?

When adding a recipient with `gopass recipients add`, their public key will automatically be exported to the store `.gpg-keys/<ID>`.

## Can gopass be used with Terraform?

Yes, there is a gopass-based [Terraform provider](https://github.com/camptocamp/terraform-provider-pass) available.

## How can I fix `"gpg: decryption failed: No secret key"` errors?

Set the `auto-expand-secmem` option in your gpg-agent.conf, if your version of GnuPG supports it.

## I'm getting `Path too long for Unix domain socket` errors, usually on MacOS.

This can be fixed by setting `export TMPDIR=/tmp` (or any other suiteable location with a path shorter than 80 characters).

## Empty secret?

Old version of `gpg` may fail to decode message encrypted with newer version without any message. The encrypted secret in such case is just empty and gopass will warn you about this. One case of such behaviour we have seen so far is when the encryption key generated with `gpg` version 2.3.x encrypt a password that is then decrypted on `gpg` version 2.2.x (default on Ubuntu 18.04). In this particular case old `gpg` does not understand `AEAD` encryption extension, and it fails without any error.  If it is your case then follw the instructions in listed in #2283.

## Expired recipients

`gopass` will refuse to add new recipients when any invalid (e.g. expired) recipients are present in a password store.
In such cases manual intervention is required. Expired keys can either be removed or extended. Unknown keys that
can not be automatically imported need to be obtained and manually imported first. These are restrictions from the underlying
crypto implementation (GPG) and we can not easily work around these.

## API Stability

This repository primarily delivers gopass as a command-line interface (CLI) tool. While the underlying Go packages might be importable, we explicitly state that semantic versioning applies solely to changes in the CLI. We offer no API stability guarantees for the Go packages within this repository, and breaking changes may occur without a major version bump of `gopass` itself.

If you choose to utilize `gopass` packages as libraries, it is strongly recommended to vendor them to mitigate potential integration issues arising from non-backward-compatible updates.

Should specific Go packages within this project prove valuable for independent use, we encourage you to request their extraction into separate repositories. In such dedicated repositories, we will adhere to strict semantic versioning principles, ensuring predictable API stability for those packages.

## Further Reading

* [GPGTools](https://gpgtools.org/) for MacOS
* [GitHub Help on GPG](https://help.github.com/articles/signing-commits-with-gpg/)
* [Git - the simple guide](http://rogerdudler.github.io/git-guide/)
