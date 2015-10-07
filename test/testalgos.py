import unittest, os, shutil, difflib, stat
from subprocess import call

class TestAlgos(unittest.TestCase):

    ciphers = [
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        #"twofish-cbc",
        #"twofish256-cbc",
        "blowfish-cbc",
        "3des-cbc",
        "cast128-cbc"
    ]
    macs = [
        "hmac-md5",
        "hmac-sha1"
    ]
    verificationErrors = []
    diffs = {}
    actualResultsBaseDir = "actualResults"
    expectedResultsBaseDir = "expectedResults"
    keysBaseDir = "keys"

    @classmethod
    def setUpClass(cls):
        if (os.path.exists(cls.actualResultsBaseDir) == True):
            shutil.rmtree(cls.actualResultsBaseDir)
        os.makedirs(cls.actualResultsBaseDir)

        if (os.path.exists(cls.keysBaseDir) == True):
            shutil.rmtree(cls.keysBaseDir)
        os.mkdir(cls.keysBaseDir)

    def myAssertEqual(self, a, b, msg=None):
        try:
            self.assertEqual(a, b, msg)
        except AssertionError as e:
            print(str(e))
            self.verificationErrors.append(str(e))

    def myAssertTrue(self, a, msg=None):
        try:
            self.assertTrue(a, msg)
        except AssertionError as e:
            print(str(e))
            self.verificationErrors.append(str(e))

    def cutTimeStamp(self, l):
        return l[24:]

    def shouldIgnore(self, l, ignoreLines):
        ignore = False
        for ignoreLine in ignoreLines:
            if (ignoreLine in l):
                ignore = True
                break;
        return ignore

    def getFileContent(self, filename, cutTimeStamp, ignoreLines):
        ret = []
        try:
            with open(filename) as f:
                for line in f:
                    l = line.strip()
                    if (cutTimeStamp == True):
                        l = self.cutTimeStamp(l)
                    if (self.shouldIgnore(l, ignoreLines) == False):
                        ret.append(l)
        except IOError:
            pass
        return sorted(ret)

    def cmpOutputFiles(self, filename, actualResultsDir, expectedResultsDir, cutTimeStamp, ignoreLines, verbose):
        verified = True
        difflist = []
        if (os.path.exists(actualResultsDir) == False):
            os.makedirs(actualResultsDir)
        shutil.copy(filename, actualResultsDir)
        os.remove(filename)
        actualResultsFileName = os.path.join(actualResultsDir, filename)
        expectedResultsFileName = os.path.join(expectedResultsDir, filename)
        actualResults = self.getFileContent(actualResultsFileName, cutTimeStamp, ignoreLines)
        expectedResults = self.getFileContent(expectedResultsFileName, cutTimeStamp, ignoreLines)
        difflist = list(difflib.context_diff(actualResults, expectedResults))
        if (verbose == True):
            self.myAssertTrue(len(actualResults) > 0, "No actual output in " + actualResultsFileName)
            self.myAssertEqual(len(difflist), 0, "Differences in: " + actualResultsFileName + " " + expectedResultsFileName)
        if (len(difflist) > 0):
            verified = False
            if (verbose == True):
                self.diffs[actualResultsFileName] = expectedResultsFileName
                for d in difflist:
                    print(d)
        return verified

    def verifyAlgos(self, cipher, mac, actualResultsFileName, verbose):
        actualResults = "\n".join(self.getFileContent(actualResultsFileName, False, []))
        verified = False
        if ((" agreed on: " + cipher in actualResults) and (" agreed on: " + mac in actualResults)):
            verified = True
        elif (verbose == True):
            self.diffs[actualResultsFileName] = os.path.join(cipher, mac)
            self.myAssertTrue(verified, "Cipher or mac not found in " + actualResultsFileName)
        return verified

    def runAlgoTest(self, password, cipher, mac, keyfile):
        for i in range(0, 2):
            cmd = "../../install/bin/cppsshtestalgos 192.168.1.19 algotester " + password + " " + cipher + " " + mac + " " + keyfile
            print("Testing: " + cmd)
            call(cmd.split(" "))
            directory = os.path.join(cipher, mac)
            if (len(keyfile) > 0):
                directory = os.path.join(directory, os.path.basename(keyfile))
            actualResultsDir = os.path.join(self.actualResultsBaseDir, directory)
            passCnt = self.verifyAlgos(cipher, mac, os.path.join(actualResultsDir, "testlog.txt"), bool(i))
            passCnt += self.cmpOutputFiles("testlog.txt", actualResultsDir, self.expectedResultsBaseDir, True, ["Kex algos", "Cipher algos", "MAC algos", "Compression algos", "Hostkey algos", " agreed on: ", "Authenticated with"], bool(i))
            passCnt += self.cmpOutputFiles("testoutput.txt", actualResultsDir, self.expectedResultsBaseDir, False, ["Last login:", "SSH_CLIENT=", "SSH_CONNECTION=", "SSH_TTY=", "DISPLAY="], bool(i))
            if (passCnt == 3):
                break

    def getKeyFilename(self, keyType, password):
        filename = ""
        if (len(keyType) > 0):
            filename = os.path.join(self.keysBaseDir, "testkey_" + keyType)
            if (password != ""):
                filename += "_pw"
        return filename

    def generateKey(self, keyType, password):
        filename = self.getKeyFilename(keyType, password)
        cmd = "ssh-keygen -t " + keyType + " -b 1024 -C test@home.com -f " + filename + " -N " + password
        print(cmd)
        call(cmd.split(" "))
        if (password != ""):
            cmd = "openssl pkcs8 -in " + filename + " -passin pass:" + password + " -topk8 -v2 des3 -out " + filename + "_new -passout pass:" + password
            print(cmd)
            call(cmd.split(" "))
            shutil.move(filename + "_new", filename)
        os.chmod(filename, stat.S_IWUSR | stat.S_IRUSR)

    def testKeys(self):
        keys = ["rsa", "dsa", ""]
        passwords = ["", "testpw"]

        for key in keys:
            for password in passwords:
                if (len(key) > 0):
                    self.generateKey(key, password)

        cmd = "../../install/bin/cppsshtestkeys 192.168.1.19 algotester password keys"
        call(cmd.split(" "))

        for key in keys:
            for password in passwords:
                for cipher in self.ciphers:
                    for mac in self.macs:
                        if (len(key) == 0):
                            password = "password"
                        self.runAlgoTest(password, cipher, mac, self.getKeyFilename(key, password))

    def tearDown(self):
        if (len(self.verificationErrors) == 0):
            print("OK")
        else:
            print("FAILED (errors=" + str(len(self.verificationErrors)) + ")")
        for k, v in self.diffs.items():
            print("diff " + k + " " + v)
        self.assertEqual(len(self.verificationErrors), 0)

if __name__ == '__main__':
    unittest.main()
