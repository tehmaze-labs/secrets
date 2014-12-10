# Secrets

Status: **work in progress**

Secrets is a repository of group encrypted blobs. Any authenticated node can
retrieve and (over)write any secret.

When adding a secret, a node first generates a random 256 bit private key,
suitable for NaCL box encryption. Nextly, it asks the secret server for all
public keys of all the receiving nodes. Then the node will generate a message
secret, encrypt this secret to all other node's public keys and pack the bundled
message. This bundled message will now be stored on the server, and can be
retrieved by any node.

## Cryptography

The secrets server uses X.509 PKI to authenticate nodes. The nodes may use
client certificates and the secrets server may verify those certificates, if
configured.

The nodes use NaCL box public key encryption to encrypt message secrets. The
message itself is symmetrically encrypted using a NaCL secret box.

## Setting up

For a quick setup, use the testdata/init script to generate a self-signed
certificate and box private key for the secrets server.

## Configuration

The secrets groups may also include a box private key stored on the server, if
for example the secrets server also has to have access to the secrets stored for
the group. You can use multiple keys in multiple groups. In most cases, it is
not desired to give the secrets server access to the group secrets. Of course
you can also include the public key of your backup box(en) in the group.

## Expanding the pool of nodes in a group

The secrets server does not take care of automagically re-encrypting secrets if
a node joins a group, because under normal circumstances the secret server has
no access to the decrypted data.
