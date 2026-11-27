"""The certificates the scenarios use, made in a directory when a run starts."""

import subprocess

REVOKED = 10000

CA = """[ca]
default_ca = d
[d]
database = {dir}/{name}.index
default_md = sha256
default_crl_days = 30
"""


def make(dir):
    def run(*args):
        subprocess.run(["openssl", *args], check=True, capture_output=True, cwd=dir)

    def signed(name, subject, issuer, extensions):
        run("req", "-newkey", "rsa:2048", "-nodes", "-subj", subject, "-keyout", f"{name}.key", "-out", f"{name}.csr")
        with open(f"{dir}/{name}.ext", "w") as f:
            f.write(extensions)
        run("x509", "-req", "-in", f"{name}.csr", "-CA", f"{issuer}.pem", "-CAkey", f"{issuer}.key", "-CAcreateserial",
            "-days", "30", "-extfile", f"{name}.ext", "-out", f"{name}.pem")

    def crl(name, revoked):
        with open(f"{dir}/{name}.cnf", "w") as f:
            f.write(CA.format(dir=dir, name=name))
        with open(f"{dir}/{name}.index", "w") as f:
            f.writelines(f"R\t351231000000Z\t251231000000Z\t{0x100000 + i:X}\tunknown\t/CN=r{i}\n" for i in range(revoked))
        run("ca", "-config", f"{name}.cnf", "-gencrl", "-keyfile", f"{name}.key", "-cert", f"{name}.pem",
            "-out", f"{name}.crl")

    # A server's, for itself, in RSA and in ECDSA. c.pem is also a client's that is trusted as it is.
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=localhost", "-keyout", "k.pem", "-out", "c.pem")
    run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2",
        "-subj", "/CN=localhost", "-keyout", "ec.key", "-out", "ec.pem")
    for name, source in (("localhost.crt", "c.pem"), ("localhost.key", "k.pem")):
        with open(f"{dir}/{source}", "rb") as f, open(f"{dir}/{name}", "wb") as g:
            g.write(f.read())
    # A client's, from an intermediate authority of a root, and what both have revoked.
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-subj", "/CN=root", "-keyout", "root.key", "-out", "root.pem")
    signed("int", "/CN=intermediate", "root", "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n")
    signed("client", "/CN=client", "int", "basicConstraints=CA:FALSE\n")
    crl("root", 0)
    crl("int", REVOKED)
    for name, parts in (("clients.pem", ("root.pem", "int.pem")), ("clients.crl", ("root.crl", "int.crl"))):
        with open(f"{dir}/{name}", "wb") as g:
            for part in parts:
                with open(f"{dir}/{part}", "rb") as f:
                    g.write(f.read())
