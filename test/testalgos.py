import unittest, os, shutil, difflib
from subprocess import call

class TestAlgos(unittest.TestCase):

    ciphers = [
        "aes256-cbc",
        "aes192-cbc",
        "twofish-cbc",
        "twofish256-cbc",
        "blowfish-cbc",
        "3des-cbc",
        "aes128-cbc",
        "cast128-cbc"
    ]
    macs = [
        "hmac-md5",
        "hmac-sha1"
    ]
    verificationErrors = []

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
        with open(filename) as f:
            for line in f:
                l = line.strip()
                if (cutTimeStamp == True):
                    l = self.cutTimeStamp(l)
                if (self.shouldIgnore(l, ignoreLines) == False):
                    ret.append(l)
        return sorted(ret)

    def cmpOutputFiles(self, filename, actualResultsDir, expectedResultsDir, cutTimeStamp, ignoreLines):
        difflist = []
        if (os.path.exists(actualResultsDir) == False):
            os.makedirs(actualResultsDir)
        shutil.copy(filename, actualResultsDir)
        os.remove(filename)
        actualResultsFileName = actualResultsDir + "/" + filename
        expectedResultsFileName = expectedResultsDir + "/" + filename
        actualResults = self.getFileContent(actualResultsFileName, cutTimeStamp, ignoreLines)
        expectedResults = self.getFileContent(expectedResultsFileName, cutTimeStamp, ignoreLines)
        difflist = list(difflib.context_diff(actualResults, expectedResults))
        self.myAssertTrue(len(actualResults) > 0, "No actual output in " + actualResultsFileName)
        self.myAssertEqual(len(difflist), 0, "Differences in: " + actualResultsFileName + " " + expectedResultsFileName)
        if (len(difflist) > 0):
            for d in difflist:
                print(d)

    def runAlgoTest(self, password, cipher, mac, keyfile = ""):
        cmd = "../../install/bin/cppsshtestalgos 192.168.1.19 algotester " + password + " " + cipher + " " + mac + " " + keyfile
        print("Testing: " + cmd)
        call(cmd.split(" "))
        actualResultsDir = "actualResults/" + cipher + "/" + mac
        expectedResultsDir = "expectedResults/" + cipher + "/" + mac
        self.cmpOutputFiles("testlog.txt", actualResultsDir, expectedResultsDir, True, ["Kex algos", "Cipher algos", "MAC algos", "Compression algos", "Hostkey algos"])
        self.cmpOutputFiles("testoutput.txt", actualResultsDir, expectedResultsDir, False, ["Last login:", "SSH_CLIENT=", "SSH_CONNECTION=", "SSH_TTY="])

    def te1stAlgos(self):
        if (os.path.exists("actualResults") == True):
            shutil.rmtree("actualResults")
        for cipher in self.ciphers:
            for mac in self.macs:
                self.runAlgoTest("password", cipher, mac)

    def getKeyFilename(self, keyType, password):
        filename = "keys/testkey_" + keyType
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

    def testKeys(self):
        if (os.path.exists("keys") == True):
            shutil.rmtree("keys")
        os.mkdir("keys")
        self.generateKey("rsa", "")
        self.generateKey("dsa", "")
        self.generateKey("rsa", "testpw")
        self.generateKey("dsa", "testpw")

    def tearDown(self):
        if (len(self.verificationErrors) == 0):
            print("OK")
        else:
            print("FAILED (errors=" + str(len(self.verificationErrors)) + ")")
        self.assertEqual(len(self.verificationErrors), 0)

if __name__ == '__main__':
    unittest.main()
