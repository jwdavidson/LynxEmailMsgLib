using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LynxEmailMsgLib.Crypto;

namespace LynxEmailMsgLib.Tests
{
    [TestClass]
    public class UnitTest_SymmetricKeyTest
    {
        [TestMethod]
        public void TestMethod1_NewSymmetricKey()
        {
            SymmetricKey sKey = new SymmetricKey();
            Assert.IsTrue(sKey.IV.Length == 16);
            Assert.IsTrue(sKey.Key.Length == 32);
        }

        [TestMethod]
        public void TestMethod2_DifferentSymmetricKeys()
        {
            SymmetricKey firstKey = new SymmetricKey();
            SymmetricKey secondKey = new SymmetricKey();
            Assert.IsTrue(firstKey.IV != secondKey.IV);
            Assert.IsTrue(firstKey.Key != secondKey.Key);
        }
    }
}
