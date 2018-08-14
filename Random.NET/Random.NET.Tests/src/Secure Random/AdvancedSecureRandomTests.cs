using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Crypto.Digests;
using RandomNET.Secure;

namespace RandomNETTests
{
    [TestClass]
    public class AdvancedSecureRandomTests
    {
        /// <summary>
        /// Same seed produces same int values.
        /// </summary>
        [TestMethod]
        public void CorrectSeededIntGeneration()
        {
            AdvancedSecureRandom secureRandom = new AdvancedSecureRandom("test seed", 312);
            AdvancedSecureRandom secureRandom2 = new AdvancedSecureRandom("test seed", 312);

            Assert.AreEqual(secureRandom.Next(), secureRandom2.Next());
            Assert.AreEqual(secureRandom.Next(100), secureRandom2.Next(100));
            Assert.AreEqual(secureRandom.Next(150, 397), secureRandom2.Next(150, 397));
        }

        /// <summary>
        /// Same seed produces same byte values.
        /// </summary>
        [TestMethod]
        public void CorrectSeededByteGeneration()
        {
            AdvancedSecureRandom secureRandom = new AdvancedSecureRandom("test seed", 312);
            AdvancedSecureRandom secureRandom2 = new AdvancedSecureRandom("test seed", 312);

            const int size = 32;
            byte[] randomBytes = secureRandom.NextBytes(size);
            byte[] randomBytes2 = secureRandom2.NextBytes(size);

            for (int i = 0; i < size; i++)
                Assert.AreEqual(randomBytes[i], randomBytes2[i]);
        }

        /// <summary>
        /// Different seed produces different values.
        /// </summary>
        [TestMethod]
        public void IncorrectSeededByteGeneration()
        {
            AdvancedSecureRandom secureRandom = new AdvancedSecureRandom(423);
            AdvancedSecureRandom secureRandom2 = new AdvancedSecureRandom("test seed", 312, 2.8372);

            Assert.AreNotEqual(secureRandom.Next(), secureRandom2.Next());
            Assert.AreNotEqual(secureRandom.Next(100), secureRandom2.Next(100));
            Assert.AreNotEqual(secureRandom.Next(150, 397), secureRandom2.Next(150, 397));
        }

        /// <summary>
        /// Same seed different digest for creating our random values.
        /// </summary>
        [TestMethod]
        public void IncorrectDigestSeededIntGeneration()
        {
            AdvancedSecureRandom secureRandom = new AdvancedSecureRandom(new Sha3Digest(), "test seed", 312);
            AdvancedSecureRandom secureRandom2 = new AdvancedSecureRandom(new WhirlpoolDigest(), "test seed", 312);

            Assert.AreNotEqual(secureRandom.Next(), secureRandom2.Next());
            Assert.AreNotEqual(secureRandom.Next(100), secureRandom2.Next(100));
            Assert.AreNotEqual(secureRandom.Next(150, 397), secureRandom2.Next(150, 397));
        }

        /// <summary>
        /// Same digest same seed produces same results.
        /// </summary>
        [TestMethod]
        public void CorrectDigestSeededIntGeneration()
        {
            AdvancedSecureRandom secureRandom = new AdvancedSecureRandom(new Blake2bDigest(), "test seed", 312);
            AdvancedSecureRandom secureRandom2 = new AdvancedSecureRandom(new Blake2bDigest(), "test seed", 312);

            Assert.AreEqual(secureRandom.Next(), secureRandom2.Next());
            Assert.AreEqual(secureRandom.Next(100), secureRandom2.Next(100));
            Assert.AreEqual(secureRandom.Next(150, 397), secureRandom2.Next(150, 397));
        }

        /// <summary>
        /// Same digest with no seeds will produce different results.
        /// </summary>
        [TestMethod]
        public void DigestIntGeneration()
        {
            AdvancedSecureRandom secureRandom = new AdvancedSecureRandom(new Sha1Digest());
            AdvancedSecureRandom secureRandom2 = new AdvancedSecureRandom(new Sha1Digest());

            Assert.AreNotEqual(secureRandom.Next(), secureRandom2.Next());
            Assert.AreNotEqual(secureRandom.Next(100), secureRandom2.Next(100));
            Assert.AreNotEqual(secureRandom.Next(150, 397), secureRandom2.Next(150, 397));
        }
    }
}
