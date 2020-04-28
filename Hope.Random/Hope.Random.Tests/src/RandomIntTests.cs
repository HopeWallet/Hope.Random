//using Microsoft.VisualStudio.TestTools.UnitTesting;
//using Org.BouncyCastle.Crypto.Digests;
//using Hope.Random;
//using Hope.Random.Numbers;

//namespace Hope.RandomTests
//{
//    [TestClass]
//    public sealed class RandomIntTests
//    {
//        [TestMethod]
//        public void DigestBitSizeDifferencesTest()
//        {
//            AdvancedSecureRandom sha3_512_random = new AdvancedSecureRandom(new Sha3Digest(512));
//            AdvancedSecureRandom sha3_256_random = new AdvancedSecureRandom(new Sha3Digest(256));

//            Assert.AreNotEqual(sha3_512_random.Next(), sha3_256_random.Next());
//        }

//        [TestMethod]
//        public void SeededFastIntGeneration()
//        {
//            Assert.AreEqual(RandomInt.Fast.GetInt(23421415, 100, 1500), RandomInt.Fast.GetInt(23421415, 100, 1500));
//        }

//        [TestMethod]
//        public void SeededSecureIntGeneration()
//        {
//            Assert.AreEqual(RandomInt.Secure.SHA3.GetInt("adsuh235qnb", 500), RandomInt.Secure.SHA3.GetInt("adsuh235qnb", 500));
//        }

//        [TestMethod]
//        public void IncorrectSeededSecureIntGeneration()
//        {
//            Assert.AreNotEqual(RandomInt.Secure.Blake2.GetInt("adsuh235qnb", 500), RandomInt.Secure.SHA3.GetInt("adsuh235qnb", 500));
//        }

//        [TestMethod]
//        public void DifferentSeedSecureIntGeneration()
//        {
//            Assert.AreNotEqual(RandomInt.Secure.SHA3.GetInt("ads3qnb", 500), RandomInt.Secure.SHA3.GetInt("adsuh235qn", 500));
//        }
//    }
//}
