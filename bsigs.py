#!/usr/bin/env python3
# A little client for m
import getpass
import click
from nacl import pwhash, secret, utils
from nacl.exceptions import CryptoError
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import Base64Encoder
from pathlib import Path
import os
import os.path
import sys
ourdir = os.path.join(Path.home(), ".bclient")
kdf = pwhash.argon2i.kdf
salt = None
ops = pwhash.argon2i.OPSLIMIT_SENSITIVE
mem = pwhash.argon2i.MEMLIMIT_SENSITIVE
pubkeyfile = os.path.join(ourdir, "blog.pub")
@click.group()
def cli():
    pass

def load_salt(p, generate=False):
    if os.path.exists(p):
        return open(p, "rb").read()
    if not generate:
        raise EOFError("No Salt file exists")
    slt = utils.random(pwhash.argon2i.SALTBYTES)
    wf = open(p, "wb")
    wf.write(slt)
    wf.close()
    return slt

def load_signkey(inDir, passwd):
    salt = load_salt(os.path.join(inDir, "bclient.salt"))
    cipherText = open(os.path.join(inDir, "blog.sec"), "rb").read()
    Wrap_key = kdf(secret.SecretBox.KEY_SIZE, passwd, salt=salt, opslimit=ops, memlimit=mem)
    sbox = secret.SecretBox(Wrap_key)
    plain = None
    try:
        plain = sbox.decrypt(cipherText)
    except CryptoError:
        raise CryptoError("Wrong password!")
    
    return plain



@cli.command()
@click.option('--outputdir', default=ourdir, help="Select output dir")

def generate(outputdir):
    """Generate a keypair"""
    print(Path.home())
    print(ourdir)
    passwd = getpass.getpass("Enter a password: ")
    repeat = getpass.getpass("repeat it: ")
    if passwd != repeat:
        click.echo("They don't match")
        return
    password = bytes(passwd, "utf-8")
    salt = load_salt(os.path.join(outputdir, "bclient.salt"), generate=True)
    Protected_Key = kdf(secret.SecretBox.KEY_SIZE, password, salt, 
        opslimit=ops, memlimit=mem)
    signkey = SigningKey.generate()
    verify_key = signkey.verify_key
    verify_key_bytes = verify_key.encode(encoder=Base64Encoder)
    
    sbox = secret.SecretBox(Protected_Key)
    nonce = utils.random(secret.SecretBox.NONCE_SIZE)
    coded = signkey.encode()
    enc_key = sbox.encrypt(coded, nonce)
    # all the writing operations sghould be done after crypto ops
    # to ensure it's atomic, we don't want partials hanging about
    # private key first as we can derive the public key from it
    priv_file = open(os.path.join(outputdir, "blog.sec"), "wb")
    priv_file.write(enc_key)
    priv_file.close()
    public_file = open(os.path.join(outputdir, "blog.pub"), "wb")
    public_file.write(verify_key_bytes)
    public_file.close()
    click.echo("keys forged")
    return

@cli.command()
@click.option('--keydir', default=ourdir, help="Select directory keys are in")
@click.option("--signfile", default="STDIN", help="File to sign default stdin")
@click.option("--outfile", default="STDOUT", help="output the signed message to")
def sign_msg(keydir, signfile, outfile):
    passwd = getpass.getpass("Enter your password: ")
    pKey = load_signkey(keydir, bytes(passwd, "utf-8"))
    rKey = SigningKey(pKey)
    click.echo("Vault opened! Ready to sign")
    if signfile == "STDIN":
        msg = sys.stdin.read()
        msg = bytes(msg, "utf-8")

    else:
        msg = open(signfile, "rb").read()
    signed = rKey.sign(msg, encoder=Base64Encoder)
    if outfile == "STDOUT":
        click.clear()
        sys.stdout.write(signed.decode("utf-8"))
    else:
        out = open(outfile, "w")
        out.write(signed.decode("utf-8"))
        
    return




@cli.command()
@click.option('--keyfile', default=pubkeyfile, help="Select directory keys are in")
@click.option("--signfile", default="STDIN", help="File to sign default stdin")

def verify_msg(keyfile, signfile):
    pKey = open(keyfile).read()
    vkBytes = Base64Encoder.decode(pKey)
    vKey = VerifyKey(vkBytes)

    if signfile == "STDIN":
        click.clear()
        click.echo("Ready to verify don't forget the sig")
        buff = sys.stdin.read()
        buffBytes = Base64Encoder.decode(buff)
        
    else:
        buff = open(signfile).read()
        
        buffBytes = Base64Encoder.decode(buff)

    try:
       msg = vKey.verify(buffBytes)
       click.echo(msg)


    except CryptoError as e:
        click.echp(str(e))
        return 1
    click.echo("OK!")
    return 0


if __name__ == '__main__':
    cli()



    