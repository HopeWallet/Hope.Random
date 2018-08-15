using Org.BouncyCastle.Crypto.Digests;
using RandomNet.Strings.Abstract;
using System;

namespace RandomNet.Strings
{
    /// <summary>
    /// Utility class used for generating random string data.
    /// </summary>
    public static class RandomString
    {
        /// <summary>
        /// Class which holds secure random string implementations.
        /// </summary>
        public static class Secure
        {
            /// <summary>
            /// Class which generates random string using the Blake2 hash function (https://en.wikipedia.org/wiki/BLAKE_(hash_function)).
            /// <para> This is the 10th fastest class for generating random string data, being ~6.9x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is considered a very secure hash algorithm. It is arguably the most secure hash algorithm used for password hashing.
            /// </summary>
            public sealed class Blake2 : RandomStringBase<Blake2bDigest> { }

            /// <summary>
            /// Class which generates random string using the MD5 hash function (https://en.wikipedia.org/wiki/MD5).
            /// <para> This is the 3rd fastest class for generating random string data, being ~3.95x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is not considered a very secure algorithm, while still being much more secure than the <see cref="Fast"/> algorithm.
            /// </summary>
            public sealed class MD5 : RandomStringBase<MD5Digest> { }

            /// <summary>
            /// Class which generates random string using the RIPEMD256 hash function (https://en.wikipedia.org/wiki/RIPEMD).
            /// <para> This is the 9th fastest class for generating random string data, being ~6.45x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is considered not as secure as the SHA family of hash functions, while it is still often used for PGP encryption.
            /// </summary>
            public sealed class RIPEMD256 : RandomStringBase<RipeMD256Digest> { }

            /// <summary>
            /// Class which generates random string using the RIPEMD320 hash function (https://en.wikipedia.org/wiki/RIPEMD).
            /// <para> This is the 11th fastest class for generating random string data, being ~8.07x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is considered not as secure as the SHA family of hash functions, while it is still often used for PGP encryption.
            /// </summary>
            public sealed class RIPEMD320 : RandomStringBase<RipeMD320Digest> { }

            /// <summary>
            /// Class which generates random string using the SHA1 hash function (https://en.wikipedia.org/wiki/SHA-1).
            /// <para> This is the 4th fastest class for generating random string data, being ~4.63x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is not considered a very secure algorithm, for more security consider using <see cref="SHA256"/>/<see cref="SHA512"/> or <see cref="SHA3"/> variants instead.
            /// </summary>
            public sealed class SHA1 : RandomStringBase<Sha1Digest> { }

            /// <summary>
            /// Class which generates random string using the SHA3 hash function (https://en.wikipedia.org/wiki/SHA-3).
            /// <para> This is the 5th fastest class for generating random string data, being ~4.67x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is considered a very secure hash algorithm as it is a subset of the Keccak family of hashing functions.
            /// </summary>
            public sealed class SHA3 : RandomStringBase<Sha3Digest> { }

            /// <summary>
            /// Class which generates random string using the SHA256 hash function (https://en.wikipedia.org/wiki/SHA-2).
            /// <para> This is the 6th fastest class for generating random string data, being ~4.95x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is considered a moderately secure hash algorithm. While it has yet to be broken, <see cref="SHA3"/> offers higher level of security.
            /// </summary>
            public sealed class SHA256 : RandomStringBase<Sha256Digest> { }

            /// <summary>
            /// Class which generates random string using the SHA512 hash function (https://en.wikipedia.org/wiki/SHA-2).
            /// <para> This is the 6th fastest class for generating random string data, being ~5x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is considered a moderately secure hash algorithm. While it has yet to be broken, <see cref="SHA3"/> offers higher level of security.
            /// </summary>
            public sealed class SHA512 : RandomStringBase<Sha512Digest> { }

            /// <summary>
            /// Class which generates random string using the SHAKE hash function (https://en.wikipedia.org/wiki/SHA-3).
            /// <para> This is the 8th fastest class for generating random string data, being ~6.32x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is considered a very secure hash algorithm as it is a subset of the Keccak family of hashing functions.
            /// </summary>
            public sealed class Shake : RandomStringBase<ShakeDigest> { }

            /// <summary>
            /// Class which generates random string using the chinese SM3 hash function (https://tools.ietf.org/id/draft-oscca-cfrg-sm3-01.html).
            /// <para> This is the 7th fastest class for generating random string data, being ~6x slower than the <see cref="Fast"/> algorithm. </para>
            /// This appears to be a secure algorithm, while it is not widely adopted and tested compared to other hash functions.
            /// </summary>
            public sealed class SM3 : RandomStringBase<SM3Digest> { }

            /// <summary>
            /// Class which generates random string using the Tiger hash function (https://en.wikipedia.org/wiki/Tiger_(hash_function)).
            /// <para> This is the 2nd fastest class for generating random string data, being ~3.6x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is generally considered less secure than <see cref="RIPEMD256"/> and <see cref="RIPEMD320"/> variants.
            /// </summary>
            public sealed class Tiger : RandomStringBase<TigerDigest> { }

            /// <summary>
            /// Class which generates random string using the Whirlpool hash function (https://en.wikipedia.org/wiki/Whirlpool_(hash_function)).
            /// <para> This is the slowest class for generating random string data, being ~18.2x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is a very niche algorithm, and has not seen wide use while being fairly secure.
            /// </summary>
            public sealed class Whirlpool : RandomStringBase<WhirlpoolDigest> { }
        }

        /// <summary>
        /// Class which generates a random string using an insecure, yet very fast algorithm. 
        /// <para> Should only be used if the random string does not need to be secure. </para>
        /// </summary>
        public static class Fast
        {
            /// <summary>
            /// Generates a random <see langword="string"/> using a fast, nonsecure algorithm.
            /// <para> Uses a default length of 16. </para>
            /// </summary>
            /// <returns> The randomly generated <see langword="string"/>. </returns>
            public static string GetString() => GetString(16);

            /// <summary>
            /// Generates a random <see langword="string"/> using a fast, nonsecure algorithm and a seed.
            /// <para> Uses a default length of 16. </para>
            /// </summary>
            /// <param name="seed"> The seed to apply to the random <see langword="string"/> generation. </param>
            /// <returns> The randomly generated <see langword="string"/>. </returns>
            public static string GetString(int? seed) => GetString(seed, 16);

            /// <summary>
            /// Generates a random <see langword="string"/> of a given length using a fast, nonsecure algorithm.
            /// </summary>
            /// <param name="length"> The length of the random <see langword="string"/>. </param>
            /// <returns> The randomly generated <see langword="string"/> </returns>
            public static string GetString(int length) => GetString(null, length);

            /// <summary>
            /// Generates a random <see langword="string"/> of a given length using a fast, nonsecure algorithm and a seed.
            /// </summary>
            /// <param name="seed"> The seed to apply to the random <see langword="string"/> generation. </param>
            /// <param name="length"> The length of the random <see langword="string"/>. </param>
            /// <returns> The randomly generated <see langword="string"/>. </returns>
            public static string GetString(int? seed, int length) => InternalGetString(seed, length);

            /// <summary>
            /// Generates a random <see langword="string"/> of a given length using a <see cref="FastRandom"/> instance and an <see langword="int"/> seed.
            /// </summary>
            /// <param name="seed"> The seed to apply to the random <see langword="string"/> generation. </param>
            /// <param name="length"> The length of the random <see langword="string"/>. </param>
            /// <returns> The randomly generated <see langword="string"/>. </returns>
            private static string InternalGetString(int? seed, int length)
            {
                byte[] bytes;
                (seed.HasValue ? new Random(seed.Value) : new Random()).NextBytes(bytes = new byte[length]);

                string randString = Convert.ToBase64String(bytes);
                return randString.Length > length ? randString.Substring(0, length) : randString; ;
            }
        }
    }
}
