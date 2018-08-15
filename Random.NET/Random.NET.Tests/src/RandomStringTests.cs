using Microsoft.VisualStudio.TestTools.UnitTesting;
using RandomNet.Strings;

namespace RandomNETTests
{
    [TestClass]
    public sealed class RandomStringTests
    {

        [TestMethod]
        public void TestStringLength()
        {
            Assert.AreEqual(RandomString.Secure.Blake2.GetString(22).Length, 22);
        }

        [TestMethod]
        public void TestSeededStringRandom()
        {
            Assert.AreEqual(RandomString.Fast.GetString(41313498, 14), RandomString.Fast.GetString(41313498, 14));
            Assert.AreEqual(RandomString.Secure.MD5.GetString("testtest", 14), RandomString.Secure.MD5.GetString("testtest", 14));
            Assert.AreNotEqual(RandomString.Secure.SHA1.GetString("testtest", 14), RandomString.Secure.MD5.GetString("testtest", 14));
            Assert.AreNotEqual(RandomString.Secure.SHA1.GetString("testtest", 14), RandomString.Secure.SHA1.GetString("test", 14));
            Assert.AreNotEqual(RandomString.Secure.Blake2.GetString("testtest", 14), RandomString.Secure.Blake2.GetString("testtest", 18));
        }
    }
}
