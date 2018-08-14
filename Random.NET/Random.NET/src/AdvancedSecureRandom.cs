using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;
using System;
using System.Text;

namespace RandomNET
{
    public sealed class AdvancedSecureRandom : Random
    {
        private readonly SecureRandom secureRandom;

        /// <summary>
        /// Initializes a generic <see cref="AdvancedSecureRandom"/> instance with no seed or digest.
        /// </summary>
        public AdvancedSecureRandom() : this((object[])null)
        {
        }

        /// <summary>
        /// Initializes a <see cref="AdvancedSecureRandom"/> instance with an array of data used as a seed.
        /// </summary>
        /// <param name="seedData"> Array of objects to use as our random seed. </param>
        public AdvancedSecureRandom(params object[] seedData) : this(new Sha3Digest(), seedData)
        {
        }

        /// <summary>
        /// Initializes a <see cref="AdvancedSecureRandom"/> instance with an instance of <see cref="IDigest"/> for our random processing.
        /// </summary>
        /// <param name="randomDigest"> The algorithm to use to use for random processing. </param>
        public AdvancedSecureRandom(IDigest randomDigest) : this(randomDigest, null)
        {
        }

        /// <summary>
        /// Initializes a <see cref="AdvancedSecureRandom"/> instance with an instance of <see cref="IDigest"/> for our random processing and an array of data used as a seed.
        /// </summary>
        /// <param name="randomDigest"> The algorithm to use to use for random processing. </param>
        /// <param name="seedData"> Array of objects to use as our random seed. </param>
        public AdvancedSecureRandom(IDigest randomDigest, params object[] seedData)
        {
            secureRandom = GetSecureRandom(randomDigest, seedData);
        }

        /// <summary>
        /// Gets the next random <see langword="int"/> from the <see cref="SecureRandom"/>.
        /// </summary>
        /// <returns> The random <see langword="int"/>. </returns>
        public override int Next() => secureRandom.Next();

        /// <summary>
        /// Gets the next random <see langword="int"/> from the <see cref="SecureRandom"/> given the max value.
        /// </summary>
        /// <param name="maxValue"> The exclusive maximum <see langword="int"/> value of the random. </param>
        /// <returns> The random <see langword="int"/>. </returns>
        public override int Next(int maxValue) => secureRandom.Next(maxValue);

        /// <summary>
        /// Gets the next random <see langword="int"/> from the <see cref="SecureRandom"/> given the min and max value.
        /// </summary>
        /// <param name="minValue"> The inclusive minimum <see langword="int"/> value of the random. </param>
        /// <param name="maxValue"> The exclusive maximum <see langword="int"/> value of the random. </param>
        /// <returns> The random <see langword="int"/>. </returns>
        public override int Next(int minValue, int maxValue) => secureRandom.Next(minValue, maxValue);

        /// <summary>
        /// Gets the next random <see langword="double"/> from the <see cref="SecureRandom"/>.
        /// </summary>
        /// <returns> The random <see langword="double"/>. </returns>
        public override double NextDouble() => secureRandom.NextDouble();

        /// <summary>
        /// Gets the next random <see langword="long"/> from the <see cref="SecureRandom"/>.
        /// </summary>
        /// <returns> The random <see langword="long"/>. </returns>
        public long NextLong() => secureRandom.NextLong();

        /// <summary>
        /// Gets the next random <see langword="byte"/> from the <see cref="SecureRandom"/>.
        /// </summary>
        /// <returns> The random <see langword="byte"/>. </returns>
        public byte NextByte() => (byte)Next(Byte.MinValue, Byte.MaxValue + 1);

        /// <summary>
        /// Gets the next random <see langword="byte"/>[] data from the <see cref="SecureRandom"/>.
        /// </summary>
        /// <param name="buffer"> The <see langword="byte"/>[] data array to store our random data. </param>
        public override void NextBytes(byte[] buffer) => secureRandom.NextBytes(buffer);

        /// <summary>
        /// Gets the next random <see langword="byte"/>[] data from the <see cref="SecureRandom"/>.
        /// </summary>
        /// <param name="length"> The length of the <see langword="byte"/>[] data. </param>
        /// <returns> The random <see langword="byte"/>[] data. </returns>
        public byte[] NextBytes(int length)
        {
            byte[] buffer;
            NextBytes(buffer = new byte[length]);

            return buffer;
        }

        /// <summary>
        /// Gets the <see cref="SecureRandom"/> instance based on our <see cref="IDigest"/> and seed data.
        /// </summary>
        /// <param name="randomDigest"> The algorithm to use to use for random processing. </param>
        /// <param name="seedData"> Array of objects to use as our random seed. </param>
        /// <returns> The <see cref="SecureRandom"/> created from our <see cref="IDigest"/> and seed. </returns>
        private SecureRandom GetSecureRandom(IDigest randomDigest, object[] seedData)
        {
            IRandomGenerator randomGenerator = new DigestRandomGenerator(randomDigest);

            if (seedData == null || seedData.Length == 0)
                randomGenerator.AddSeedMaterial(SecureRandom.GetNextBytes(new SecureRandom(), 16));
            else
                foreach (var seed in seedData) randomGenerator.AddSeedMaterial(seed.GetType() == typeof(byte[]) ? (byte[])seed : Encoding.UTF8.GetBytes(seed.ToString()));

            return new SecureRandom(randomGenerator);
        }
    }
}
