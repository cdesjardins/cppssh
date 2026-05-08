#!/usr/bin/env python3
import unittest, os, shutil, stat, random, argparse, sys, getpass, atexit, time
from subprocess import call

from cryptography.hazmat.primitives import serialization

HOSTNAME = "localhost"
USERNAME = getpass.getuser()
ENCRYPT_PASSPHRASE = "testpw"
AUTHORIZED_KEYS = os.path.expanduser("~/.ssh/authorized_keys")
SSH_DIR = os.path.expanduser("~/.ssh")

# Populated in main() before unittest runs so getpass interacts with the real TTY.
LOGIN_PASSWORD = ""

# Module-level so atexit can restore even if tearDownClass is skipped.
_authorized_keys_backup = None
_keys_base_dir_to_clean = None


def _restore_authorized_keys():
    global _authorized_keys_backup
    if _authorized_keys_backup is None:
        return
    try:
        if _authorized_keys_backup == "__none__":
            if os.path.exists(AUTHORIZED_KEYS):
                os.remove(AUTHORIZED_KEYS)
        else:
            shutil.move(_authorized_keys_backup, AUTHORIZED_KEYS)
            os.chmod(AUTHORIZED_KEYS, stat.S_IRUSR | stat.S_IWUSR)
    finally:
        _authorized_keys_backup = None


def _cleanup_keys_dir():
    global _keys_base_dir_to_clean
    if _keys_base_dir_to_clean and os.path.exists(_keys_base_dir_to_clean):
        shutil.rmtree(_keys_base_dir_to_clean, ignore_errors=True)
    _keys_base_dir_to_clean = None


atexit.register(_restore_authorized_keys)
atexit.register(_cleanup_keys_dir)


class TestAlgos(unittest.TestCase):

    ciphers = [
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr"
    ]
    macs = [
        "hmac-sha2-256",
        "hmac-sha2-512"
    ]
    # (label, ssh-keygen extra args). Label is also the on-disk filename suffix.
    keyTypes = [
        ("rsa",       ["-t", "rsa",     "-b", "3072"]),
        ("ecdsa-256", ["-t", "ecdsa",   "-b", "256"]),
        ("ecdsa-384", ["-t", "ecdsa",   "-b", "384"]),
        ("ecdsa-521", ["-t", "ecdsa",   "-b", "521"]),
        ("ed25519",   ["-t", "ed25519"]),
    ]
    # Whether each generated key gets an encrypting passphrase ("") or not.
    keyPassphraseModes = ["", ENCRYPT_PASSPHRASE]

    testCases = []
    verificationErrors = []
    diffs = {}
    actualResultsBaseDir = "actualResults"
    keysBaseDir = "keys"

    @classmethod
    def setUpClass(cls):
        global _keys_base_dir_to_clean

        # Build the test case matrix: every (key, encrypted-or-not) crossed with
        # cipher x mac, plus a password-auth row (empty key) if a login password
        # was provided.
        for label, _ in cls.keyTypes:
            for passphrase in cls.keyPassphraseModes:
                for cipher in cls.ciphers:
                    for mac in cls.macs:
                        cls.testCases.append({
                            "keyLabel": label,
                            "keyPassphrase": passphrase,
                            "cipher": cipher,
                            "mac": mac,
                        })
        if LOGIN_PASSWORD:
            for cipher in cls.ciphers:
                for mac in cls.macs:
                    cls.testCases.append({
                        "keyLabel": "",
                        "keyPassphrase": "",
                        "cipher": cipher,
                        "mac": mac,
                    })

        if args.all is False:
            cls.setupSubset()

        if os.path.exists(cls.actualResultsBaseDir):
            shutil.rmtree(cls.actualResultsBaseDir)
        os.makedirs(cls.actualResultsBaseDir)

        if os.path.exists(cls.keysBaseDir):
            shutil.rmtree(cls.keysBaseDir)
        os.mkdir(cls.keysBaseDir)
        _keys_base_dir_to_clean = os.path.abspath(cls.keysBaseDir)

        # Generate every key variant we'll use.
        for label, kgArgs in cls.keyTypes:
            for passphrase in cls.keyPassphraseModes:
                cls.generateKey(label, kgArgs, passphrase)

        cls.installAuthorizedKeys()

    @classmethod
    def tearDownClass(cls):
        _restore_authorized_keys()
        _cleanup_keys_dir()

    @classmethod
    def setupSubset(cls):
        print("Running a subset of tests\n\n\n")
        random.seed()
        # Keep ~1/5 of the cases.
        numToRemove = len(cls.testCases) - (len(cls.testCases) // 5)
        for _ in range(numToRemove):
            index = random.randint(0, len(cls.testCases) - 1)
            cls.testCases.remove(cls.testCases[index])

    @classmethod
    def keyFilename(cls, label, passphrase):
        if not label:
            return ""
        name = "testkey_" + label.replace("-", "_")
        if passphrase:
            name += "_pw"
        return os.path.join(cls.keysBaseDir, name)

    @classmethod
    def generateKey(cls, label, keygenArgs, passphrase):
        """Generate a key with ssh-keygen, then re-serialize the private half as
        PKCS8 PEM so Botan (used by cppssh) can load it for every key family
        including ed25519 (whose ssh-keygen output is OpenSSH-only)."""
        filename = cls.keyFilename(label, passphrase)
        # ssh-keygen with -N "" produces an unencrypted key; we always do that
        # and apply encryption ourselves below via the cryptography library.
        cmd = ["ssh-keygen"] + keygenArgs + [
            "-C", "test@home.com", "-f", filename, "-N", "",
        ]
        if os.path.exists(filename):
            os.remove(filename)
        if os.path.exists(filename + ".pub"):
            os.remove(filename + ".pub")
        print(" ".join(cmd))
        if call(cmd) != 0:
            raise RuntimeError("ssh-keygen failed for " + label)

        with open(filename, "rb") as f:
            privBytes = f.read()
        privKey = serialization.load_ssh_private_key(privBytes, password=None)

        if passphrase:
            enc = serialization.BestAvailableEncryption(passphrase.encode())
        else:
            enc = serialization.NoEncryption()
        pkcs8 = privKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )
        with open(filename, "wb") as f:
            f.write(pkcs8)
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)

    @classmethod
    def installAuthorizedKeys(cls):
        """Back up the user's authorized_keys file and append every generated
        public key. Restoration happens via atexit + tearDownClass."""
        global _authorized_keys_backup

        if not os.path.isdir(SSH_DIR):
            os.makedirs(SSH_DIR, mode=0o700)

        if os.path.exists(AUTHORIZED_KEYS):
            backup = AUTHORIZED_KEYS + ".cppsshtestbackup." + str(int(time.time()))
            shutil.copy2(AUTHORIZED_KEYS, backup)
            _authorized_keys_backup = backup
        else:
            _authorized_keys_backup = "__none__"

        with open(AUTHORIZED_KEYS, "ab") as out:
            out.write(b"\n# cppssh test keys -- removed at end of run\n")
            for label, _ in cls.keyTypes:
                for passphrase in cls.keyPassphraseModes:
                    pubFile = cls.keyFilename(label, passphrase) + ".pub"
                    with open(pubFile, "rb") as pf:
                        out.write(pf.read())
        os.chmod(AUTHORIZED_KEYS, stat.S_IRUSR | stat.S_IWUSR)

    @staticmethod
    def stashFile(filename, destDir):
        """Move filename (if present) into destDir and return its new path."""
        if not os.path.exists(filename):
            return None
        if not os.path.exists(destDir):
            os.makedirs(destDir)
        dest = os.path.join(destDir, filename)
        shutil.move(filename, dest)
        return dest

    @staticmethod
    def readText(path):
        if path is None:
            return ""
        try:
            with open(path, errors="replace") as f:
                return f.read()
        except IOError:
            return ""

    def runAlgoTest(self, password, cipher, mac, keyfile, label):
        cmd = [
            "../../install/bin/cppsshtestalgos",
            HOSTNAME, USERNAME, password, cipher, mac,
        ]
        if keyfile:
            cmd.append(keyfile)
        # Redact the password slot before logging the command line.
        printable = list(cmd)
        printable[3] = "***" if password else ""
        print("Testing " + label + ": " + " ".join(printable))
        rc = call(cmd)

        directory = os.path.join(cipher, mac, label)
        actualResultsDir = os.path.join(self.actualResultsBaseDir, directory)
        logPath = self.stashFile("testlog.txt", actualResultsDir)
        outPath = self.stashFile("testoutput.txt", actualResultsDir)
        logText = self.readText(logPath)
        outText = self.readText(outPath)

        failures = []
        if rc != 0:
            failures.append("binary exit code " + str(rc))
        # The remote prompt is typically "user@host:~$ ", which never reduces to
        # a line that is exactly the username -- so checking for the username on
        # its own line cleanly distinguishes whoami's reply from the prompt.
        outLines = [l.strip() for l in outText.splitlines()]
        if USERNAME not in outLines:
            failures.append("expected username " + repr(USERNAME) +
                            " not found on its own line in " + (outPath or "testoutput.txt"))
        if (" agreed on: " + cipher) not in logText:
            failures.append("cipher " + cipher + " not negotiated (no 'agreed on' entry in " +
                            (logPath or "testlog.txt") + ")")
        if (" agreed on: " + mac) not in logText:
            failures.append("mac " + mac + " not negotiated (no 'agreed on' entry in " +
                            (logPath or "testlog.txt") + ")")

        if failures:
            msg = "FAIL " + label + ":\n  " + "\n  ".join(failures)
            print(msg)
            self.verificationErrors.append(msg)
            self.diffs[label] = actualResultsDir
        else:
            print("PASS " + label)

    def testKeys(self):
        for tc in self.testCases:
            keyLabel = tc["keyLabel"]
            passphrase = tc["keyPassphrase"]
            cipher = tc["cipher"]
            mac = tc["mac"]

            keyfile = self.keyFilename(keyLabel, passphrase)
            if keyfile:
                # Key auth: pass the encrypting passphrase (or "") so the binary
                # can decrypt the private key.
                authPassword = passphrase
                authLabel = os.path.basename(keyfile)
            else:
                # Password auth: use the user's real login password.
                authPassword = LOGIN_PASSWORD
                authLabel = "password"

            caseLabel = cipher + "/" + mac + "/" + authLabel
            self.runAlgoTest(authPassword, cipher, mac, keyfile, caseLabel)

    def tearDown(self):
        if len(self.verificationErrors) == 0:
            print("OK")
        else:
            print("FAILED (errors=" + str(len(self.verificationErrors)) + ")")
            for label, resultsDir in self.diffs.items():
                print("  " + label + " -> " + resultsDir)
        self.assertEqual(len(self.verificationErrors), 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true",
                        help="Run every (key, cipher, mac) combination instead of a random ~1/5 subset.")
    parser.add_argument("--no-password-auth", action="store_true",
                        help="Skip the password-auth test cases and don't prompt for a login password.")
    parser.add_argument("unittest_args", nargs="*")
    args = parser.parse_args()

    if not args.no_password_auth:
        try:
            LOGIN_PASSWORD = getpass.getpass(
                "Login password for " + USERNAME + "@" + HOSTNAME +
                " (Enter to skip password-auth tests): "
            )
        except (EOFError, KeyboardInterrupt):
            LOGIN_PASSWORD = ""
        if not LOGIN_PASSWORD:
            print("No password provided -- password-auth tests will be skipped.")

    sys.argv[1:] = args.unittest_args
    unittest.main()
