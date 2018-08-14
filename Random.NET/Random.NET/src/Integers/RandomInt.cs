using Org.BouncyCastle.Crypto.Digests;

namespace RandomNET.Integers
{
    using FastRandom = System.Random;

    /// <summary>
    /// Utility class used for generating random int data.
    /// </summary>
    public static class RandomInt
    {
        /// <summary>
        /// Class which holds secure random integer implementations.
        /// </summary>
        public static class Secure
        {
            /// <summary>
            /// Class which generates random integers using the Blake2 hash function (https://en.wikipedia.org/wiki/BLAKE_(hash_function)).
            /// <para> This is the 10th fastest class for generating random int data, being ~6.9x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is considered a very secure hash algorithm. It is arguably the most secure hash algorithm used for password hashing.
            /// </summary>
            public sealed class Blake2 : RandomIntBase<Blake2bDigest> { }

            /// <summary>
            /// Class which generates random integers using the MD5 hash function (https://en.wikipedia.org/wiki/MD5).
            /// <para> This is the 3rd fastest class for generating random int data, being ~3.95x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is not considered a very secure algorithm, while still being much more secure than the <see cref="Fast"/> algorithm.
            /// </summary>
            public sealed class MD5 : RandomIntBase<MD5Digest> { }

            /// <summary>
            /// Class which generates random integers using the RIPEMD256 hash function (https://en.wikipedia.org/wiki/RIPEMD).
            /// <para> This is the 9th fastest class for generating random int data, being ~6.45x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is considered not as secure as the SHA family of hash functions, while it is still often used for PGP encryption.
            /// </summary>
            public sealed class RIPEMD256 : RandomIntBase<RipeMD256Digest> { }

            /// <summary>
            /// Class which generates random integers using the RIPEMD320 hash function (https://en.wikipedia.org/wiki/RIPEMD).
            /// <para> This is the 11th fastest class for generating random int data, being ~8.07x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is considered not as secure as the SHA family of hash functions, while it is still often used for PGP encryption.
            /// </summary>
            public sealed class RIPEMD320 : RandomIntBase<RipeMD320Digest> { }

            /// <summary>
            /// Class which generates random integers using the SHA1 hash function (https://en.wikipedia.org/wiki/SHA-1).
            /// <para> This is the 4th fastest class for generating random int data, being ~4.63x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is not considered a very secure algorithm, for more security consider using <see cref="SHA256"/>/<see cref="SHA512"/> or <see cref="SHA3"/> variants instead.
            /// </summary>
            public sealed class SHA1 : RandomIntBase<Sha1Digest> { }

            /// <summary>
            /// Class which generates random integers using the SHA3 hash function (https://en.wikipedia.org/wiki/SHA-3).
            /// <para> This is the 5th fastest class for generating random int data, being ~4.67x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is considered a very secure hash algorithm as it is a subset of the Keccak family of hashing functions.
            /// </summary>
            public sealed class SHA3 : RandomIntBase<Sha3Digest> { }

            /// <summary>
            /// Class which generates random integers using the SHA256 hash function (https://en.wikipedia.org/wiki/SHA-2).
            /// <para> This is the 6th fastest class for generating random int data, being ~4.95x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is considered a moderately secure hash algorithm. While it has yet to be broken, <see cref="SHA3"/> offers higher level of security.
            /// </summary>
            public sealed class SHA256 : RandomIntBase<Sha256Digest> { }

            /// <summary>
            /// Class which generates random integers using the SHA512 hash function (https://en.wikipedia.org/wiki/SHA-2).
            /// <para> This is the 6th fastest class for generating random int data, being ~5x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is considered a moderately secure hash algorithm. While it has yet to be broken, <see cref="SHA3"/> offers higher level of security.
            /// </summary>
            public sealed class SHA512 : RandomIntBase<Sha512Digest> { }

            /// <summary>
            /// Class which generates random integers using the SHAKE hash function (https://en.wikipedia.org/wiki/SHA-3).
            /// <para> This is the 8th fastest class for generating random int data, being ~6.32x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is considered a very secure hash algorithm as it is a subset of the Keccak family of hashing functions.
            /// </summary>
            public sealed class Shake : RandomIntBase<ShakeDigest> { }

            /// <summary>
            /// Class which generates random integers using the chinese SM3 hash function (https://tools.ietf.org/id/draft-oscca-cfrg-sm3-01.html).
            /// <para> This is the 7th fastest class for generating random int data, being ~6x slower than the <see cref="Fast"/> algorithm. </para>
            /// This appears to be a secure algorithm, while it is not widely adopted and tested compared to other hash functions.
            /// </summary>
            public sealed class SM3 : RandomIntBase<SM3Digest> { }

            /// <summary>
            /// Class which generates random integers using the Tiger hash function (https://en.wikipedia.org/wiki/Tiger_(hash_function)).
            /// <para> This is the 2nd fastest class for generating random int data, being ~3.6x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is generally considered less secure than <see cref="RIPEMD256"/> and <see cref="RIPEMD320"/> variants.
            /// </summary>
            public sealed class Tiger : RandomIntBase<TigerDigest> { }

            /// <summary>
            /// Class which generates random integers using the Whirlpool hash function (https://en.wikipedia.org/wiki/Whirlpool_(hash_function)).
            /// <para> This is the slowest class for generating random int data, being ~18.2x slower than the <see cref="Fast"/> algorithm. </para>
            /// This is a very niche algorithm, and has not seen wide use while being fairly secure.
            /// </summary>
            public sealed class Whirlpool : RandomIntBase<WhirlpoolDigest> { }
        }
 
        /// <summary>
        /// Class which generates random integers using an insecure, yet very fast algorithm. 
        /// <para> Should only be used if the random integers do not need to be secure. </para>
        /// </summary>
        public static class Fast
        {
            /// <summary>
            /// Gets the next random integer of this algorithm.
            /// </summary>
            /// <returns> The randomly generated integer. </returns>
            public static int GetInt() => InternalGetInt(null, null, null);

            /// <summary>
            /// Gets the next random integer of this algorithm given a seed.
            /// </summary>
            /// <param name="seed"> The seed to use to produce the random integer. </param>
            /// <returns> The randomly generated integer. </returns>
            public static int GetInt(int? seed) => InternalGetInt(seed, null, null);

            /// <summary>
            /// Gets the next random integer of this algorithm given the maximum value.
            /// </summary>
            /// <param name="maxValue"> The exclusive maximum value of the random integer. </param>
            /// <returns> The randomly generated integer. </returns>
            public static int GetInt(int maxValue) => InternalGetInt(null, null, maxValue);

            /// <summary>
            /// Gets the next random integer of this algorithm given a seed and the maximum value.
            /// </summary>
            /// <param name="seed"> The seed to use to produce the random integer. </param>
            /// <param name="maxValue"> The exclusive maximum value of the random integer. </param>
            /// <returns> The randomly generated integer. </returns>
            public static int GetInt(int? seed, int maxValue) => InternalGetInt(seed, null, maxValue);

            /// <summary>
            /// Gets the next random integer of this algorithm given the minimum and maximum value.
            /// </summary>
            /// <param name="minValue"> The inclusive minimum value of the random integer. </param>
            /// <param name="maxValue"> The exclusive maximum value of the random integer. </param>
            /// <returns> The randomly generated integer. </returns>
            public static int GetInt(int minValue, int maxValue) => InternalGetInt(null, minValue, maxValue);

            /// <summary>
            /// Gets the next random integer of this algorithm given the a seed, as well as minimum and maximum values.
            /// </summary>
            /// <param name="seed"> The seed to use to produce the random integer. </param>
            /// <param name="minValue"> The inclusive minimum value of the random integer. </param>
            /// <param name="maxValue"> The exclusive maximum value of the random integer. </param>
            /// <returns> The randomly generated integer. </returns>
            public static int GetInt(int? seed, int minValue, int maxValue) => InternalGetInt(seed, minValue, maxValue);

            /// <summary>
            /// Gets the next random integer given all parameters.
            /// </summary>
            /// <param name="seed"> The seed to use to produce the random integer. </param>
            /// <param name="minValue"> The inclusive minimum value of the random integer. </param>
            /// <param name="maxValue"> The exclusive maximum value of the random integer. </param>
            /// <returns> The randomly generated integer. </returns>
            private static int InternalGetInt(int? seed, int? minValue, int? maxValue)
            {
                FastRandom random = (seed.HasValue ? new FastRandom(seed.Value) : new FastRandom());

                if (minValue.HasValue && maxValue.HasValue)
                    return random.Next(minValue.Value, maxValue.Value);
                else if (maxValue.HasValue)
                    return random.Next(maxValue.Value);
                else
                    return random.Next();
            }
        }
    }
}