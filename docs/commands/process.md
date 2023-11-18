# `process` command

The `process` command extends the `gopass` templating to support user-supplied
template files that will be processed. These templates can access the users
credentials with the template functions documented below. That way users can
store their full configuration files publicly accessible and have any of the
recipients automatically populate it to generate a complete configuration file
on the fly.

`gopass process` writes the result to `STDOUT`. You'll likely want to redirect
it to a file.

## Synopsis

```
$ gopass process <TEMPLATE> > <OUTPUT>
```

## Flags

None.

## Examples

The templates are processed using Go's [`text/template`](https://pkg.go.dev/text/template) package.
A set of helpful template functions is added to the template. See below for a list.

### Populate a MySQL configuration

```
$ cat /etc/mysql/my.cnf.tpl
[client]
host=127.0.0.1
port=3306
user={{ getval "server/local/mysql" "username" }}
password={{ getpw "server/local/mysql" }}
$ gopass process /etc/mysql/my.cnf.tpl
[client]
host=127.0.0.1
port=3306
user=admin
password=hunter2
```

## Template functions

Function | Example | Description
-------- | ------- | -----------
`get` | `{{ get "foo/bar" }}` | Insert the full secret.
`getpw` | `{{ getpw "foo/bar" }}` | Insert the value of the password field from the given secret.
`getval` | `{{ getval "foo/bar" "baz" }}` | Insert the value of the named field from the given secret.
`argon2i` | `{{ getpw "foo/bar" \| argon2i }}` | Calculate the Argon2i hash of the input.
`argon2id` | `{{ getpw "foo/bar" \| argon2id }}` | Calculate the Argon2id hash of the input.
`blake3` | `{{ getpw "foo/bar" \| blake3 }}` | Calculate the BLAKE-3 hash of the input.
