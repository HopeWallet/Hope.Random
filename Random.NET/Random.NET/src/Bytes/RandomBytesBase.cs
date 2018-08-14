using Org.BouncyCastle.Crypto;
using RandomNET.Secure;
using System.Text;

namespace RandomNET.Bytes.Abstract
{
    /// <summary>
    /// Base class used for generating random bytes.
    /// </summary>
    /// <typeparam name="T"> The hash algorithm to use to generate our random bytes. </typeparam>
    public abstract class RandomBytesBase<T> where T : IDigest, new()
    {
        /// <summary>
        /// Generates a series of random <see langword="byte"/>[] data using the specified algorithm.
        /// </summary>
        /// <param name="length"> The length of the <see langword="byte"/>[] data. </param>
        /// <returns> The random <see langword="byte"/>[] data. </returns>
        public static byte[] GetBytes(int length) => GetBytes((byte[])null, length);

        /// <summary>
        /// Generates a series of random <see langword="byte"/>[] data using the specified algorithm and an additional <see langword="string"/> seed.
        /// </summary>
        /// <param name="seed"> The <see langword="string"/> seed to apply random <see langword="byte"/>[] generation. </param>
        /// <param name="length"> The length of the <see langword="byte"/>[] data. </param>
        /// <returns> The random <see langword="byte"/>[] data. </returns>
        public static byte[] GetBytes(string seed, int length) => GetBytes(Encoding.UTF8.GetBytes(seed), length);

        /// <summary>
        /// Generates a series of random <see langword="byte"/>[] data using the specified algorithm and an additional <see langword="byte"/>[] seed.
        /// </summary>
        /// <param name="seed"> The <see langword="byte"/>[] seed to apply random <see langword="byte"/>[] generation. </param>
        /// <param name="length"> The length of the <see langword="byte"/>[] data. </param>
        /// <returns> The random <see langword="byte"/>[] data. </returns>
        public static byte[] GetBytes(byte[] seed, int length) => GetBytes(seed, length, new T());

        /// <summary>
        /// Generates a series of random <see langword="byte"/>[] data using a specific <see cref="IDigest"/> and an additional <see langword="byte"/>[] seed.
        /// </summary>
        /// <param name="seed"> The <see langword="byte"/>[] seed to apply random <see langword="byte"/>[] generation. </param>
        /// <param name="length"> The length of the <see langword="byte"/>[] data. </param>
        /// <param name="digest"> The <see cref="IDigest"/> object to use to generate the <see langword="byte"/>[] data. </param>
        /// <returns> The random <see langword="byte"/>[] data. </returns>
        private static byte[] GetBytes(byte[] seed, int length, IDigest digest)
        {
            return (seed == null ? new AdvancedSecureRandom(digest) : new AdvancedSecureRandom(digest, seed)).NextBytes(length);
        }
    }
}
