using Microsoft.VisualStudio.TestTools.UnitTesting;
using RandomNET.Secure;

namespace RandomNETTests
{
    [TestClass]
    public sealed class RandomSeedTests
    {
        [TestClass]
        public sealed class SeedClass : IRandomSeed
        {
            private readonly byte[] seed;

            public byte[] Seed => seed ?? (new byte[] { 5, 32, 81, 4, 27, 84, 22, 84, 96, 128, 82, 192 });

            public SeedClass(byte[] seed)
            {
                this.seed = seed;
            }
        }

        [TestMethod]
        public void IncorrectSeedClass()
        {
            AdvancedSecureRandom secureRandom = new AdvancedSecureRandom(new SeedClass(null));
            AdvancedSecureRandom secureRandom2 = new AdvancedSecureRandom(new SeedClass(new byte[] { 1, 5, 4 }));

            Assert.AreNotEqual(secureRandom.Next(), secureRandom2.Next());
        }

        [TestMethod]
        public void CorrectSeedClass()
        {
            AdvancedSecureRandom secureRandom = new AdvancedSecureRandom(new SeedClass(null));
            AdvancedSecureRandom secureRandom2 = new AdvancedSecureRandom(new SeedClass(null));

            Assert.AreEqual(secureRandom.Next(), secureRandom2.Next());
        }
    }
}
