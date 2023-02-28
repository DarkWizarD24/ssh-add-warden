#!/usr/bin/env python3

import os
import tempfile
from pathlib import Path

import click
import bitwardentools

if os.name == 'nt':
    from wexpect import spawn, EOF
    import win32api
    import win32security
    import ntsecuritycon as con
else:
    from pexpect import spawn, EOF

def ssh_add(key_file, passphrase):
    """Add a ssh key file with a passphrase to ssh-agent
    
    key_file -- Path to the key
    passphrase -- Key file passphrases
    """
    sshadd = spawn('ssh-add', [str(key_file)])

    sshadd.expect("Enter passphrase for.*: ")
    sshadd.sendline(passphrase)

    passphrase_result = sshadd.expect(["Bad passphrase, try again for key: ", EOF])
    if passphrase_result == 0:
        sshadd.close()
        raise Exception("Incorrect passphrase") 

    sshadd.close()


def ssh_add_from_warden(server, email, password, identity):
    """Add a ssh key from a vault to ssh-agent

    Expect an identity with an attach private key that is protected with a passkey.
    The identity should also have a field 'key.private' with the name if the key file
    and a field 'key.passphrase' with its passphrase.

    server -- URL of the vault server
    email -- User email address
    password -- User password
    identity -- Identity in the vault that contains the certificate
    """

    #Get the cipher
    client = bitwardentools.Client(server, email, password)
    client.sync()
    try:
        cipher = list(client.get_ciphers()["name"][identity].values())[0]
    except KeyError as e:
        if identity not in str(e):
            raise
        else:
            raise Exception(identity + " not found")

    #Get information about the key
    key_private = None
    key_passphrase = None
    for field in cipher.fields:
        if field["name"] == "key.private":
             key_private = field["value"]
        elif field["name"] == "key.passphrase":
             key_passphrase = field["value"]

    if key_private is None:
        raise Exception(identity + " has no field name key.private")
    if key_passphrase is None:
        raise Exception(identity + " has no field name key.passphrase")

    #Extract the key
    with tempfile.TemporaryDirectory() as tmpdirname:
        path = None
        for attachment in cipher.attachments:
            if attachment['fileName'] == key_private:
                client.download(attachment, directory=tmpdirname, filename=key_private)
                path = Path(tmpdirname) / Path(key_private)
                #Limits access to the key file to be compatible with ssh-add
                if os.name == 'nt':
                    sd = win32security.GetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION)
                    dacl = win32security.ACL()
                    user, _, _ = win32security.LookupAccountName("", win32api.GetUserName())
                    dacl.AddAccessAllowedAce (win32security.ACL_REVISION, con.FILE_GENERIC_READ | con.FILE_GENERIC_WRITE, user)
                    sd.SetSecurityDescriptorDacl (1, dacl, 0)
                    win32security.SetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION, sd)
                else:
                    os.chmod(path, 600)

        if path is None:
            raise Exception(identity + " does not contain the attachment " + key_private)

        #Add the key
        ssh_add(path, key_passphrase)


@click.command()
@click.option('-s', '--server', help="URL of the vault server")
@click.option('-e', '--email', help="User email address")
@click.option("--password", prompt=True, hide_input=True, help="User password")
@click.option('-i', '--identity', help="Identity in the vault that contains the certificate")
def ssh_add_from_warden_cmd(server, email, password, identity):
    """Add a ssh key from a vault to ssh-agent

    Expect an identity with an attach private key that is protected with a passkey.
    The identity should also have a field 'key.private' with the name if the key file
    and a field 'key.passphrase' with its passphrase.
    """
    ssh_add_from_warden(server, email, password, identity)


if __name__ == '__main__':
    ssh_add_from_warden_cmd()
