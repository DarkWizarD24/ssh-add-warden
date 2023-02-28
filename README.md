# ssh-add-warden

Allow you to add an identity to the authentication agent from a bitwarden or vaultwarden identity.

## OS support

Tested on windows, may works on Linux.

## How to use

### Add the certificate to the identity

You can use any identity, simply add a private key protected by a passphrase as an attachment.

Then add two fields:
  - `key.private` with the name of the attached key as value
  - `key.passphrase` with the password of the attached key as value

### Use the script

Call the script with the needed parameter, it will ask your password as a prompt:
```
ssh-add-warden -s https://myvault.test.com -e user@test.com -i an_identity_with_a_certificate
```