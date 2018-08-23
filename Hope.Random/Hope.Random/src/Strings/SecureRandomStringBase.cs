using Org.BouncyCastle.Crypto;
using System;
using System.Text;

namespace Hope.Random.Strings.Abstract
{
    /// <summary>
    /// Base class used for generating secure random strings.
    /// </summary>
    /// <typeparam name="T"> The hash algorithm to use to generate our random strings. </typeparam>
    public abstract class SecureRandomStringBase<T> where T : IDigest, new()
    {
        /// <summary>
        /// Generates a random <see langword="string"/> using the specified algorithm.
        /// <para> Uses a default length of 16. </para>
        /// </summary>
        /// <returns> The randomly generated <see langword="string"/>. </returns>
        public static string GetString() => GetString(16);

        /// <summary>
        /// Generates a random <see langword="string"/> using the specified algorithm and a seed.
        /// <para> Uses a default length of 16. </para>
        /// </summary>
        /// <param name="seed"> The seed to apply to the random <see langword="string"/> generation. </param>
        /// <returns> The randomly generated <see langword="string"/>. </returns>
        public static string GetString(string seed) => GetString(Encoding.UTF8.GetBytes(seed));

        /// <summary>
        /// Generates a random <see langword="string"/> using the specified algorithm and a seed.
        /// <para> Uses a default length of 16. </para>
        /// </summary>
        /// <param name="seed"> The seed to apply to the random <see langword="string"/> generation. </param>
        /// <returns> The randomly generated <see langword="string"/>. </returns>
        public static string GetString(byte[] seed) => GetString(seed, 16);

        /// <summary>
        /// Generates a random <see langword="string"/> of a given length using the specified algorithm.
        /// </summary>
        /// <param name="length"> The length of the random <see langword="string"/>. </param>
        /// <returns> The randomly generated <see langword="string"/> </returns>
        public static string GetString(int length) => GetString((byte[])null, length);

        /// <summary>
        /// Generates a random <see langword="string"/> of a given length using the specified algorithm and a seed.
        /// </summary>
        /// <param name="seed"> The seed to apply to the random <see langword="string"/> generation. </param>
        /// <param name="length"> The length of the random <see langword="string"/>. </param>
        /// <returns> The randomly generated <see langword="string"/>. </returns>
        public static string GetString(string seed, int length) => GetString(Encoding.UTF8.GetBytes(seed), length);

        /// <summary>
        /// Generates a random <see langword="string"/> of a given length using the specified algorithm and a seed.
        /// </summary>
        /// <param name="seed"> The seed to apply to the random <see langword="string"/> generation. </param>
        /// <param name="length"> The length of the random <see langword="string"/>. </param>
        /// <returns> The randomly generated <see langword="string"/>. </returns>
        public static string GetString(byte[] seed, int length) => InternalGetString(seed, length, new T());

        /// <summary>
        /// Generates a random <see langword="string"/> of a given length using the specified <see cref="IDigest"/> and a seed.
        /// </summary>
        /// <param name="seed"> The seed to apply to the random <see langword="string"/> generation. </param>
        /// <param name="length"> The length of the random <see langword="string"/>. </param>
        /// <param name="digest"> The <see cref="IDigest"/> object to use to generate the random <see langword="string"/>. </param>
        /// <returns> The randomly generated <see langword="string"/>. </returns>
        private static string InternalGetString(byte[] seed, int length, IDigest digest)
        {
            string randString = Convert.ToBase64String((seed == null
                ? new AdvancedSecureRandom(digest)
                : new AdvancedSecureRandom(digest, seed)).NextBytes(length));

            return randString.Length > length ? randString.Substring(0, length) : randString;
        }
    }
}