using Org.BouncyCastle.Crypto;
using RandomNET.Secure;
using System.Text;

namespace RandomNET.Integers
{
    /// <summary>
    /// Base class used for generating random integers.
    /// </summary>
    /// <typeparam name="T"> The hash algorithm to use to generate our random integers. </typeparam>
    public abstract class RandomIntBase<T> where T : IDigest, new()
    {
        /// <summary>
        /// Gets the next random integer of this algorithm.
        /// </summary>
        /// <returns> The randomly generated integer. </returns>
        public static int GetInt() => InternalGetInt(null, null, null);

        /// <summary>
        /// Gets the next random integer of this algorithm given a seed.
        /// </summary>
        /// <param name="seed"> The <see langword="byte"/>[] seed to use to produce the random integer. </param>
        /// <returns> The randomly generated integer. </returns>
        public static int GetInt(byte[] seed) => InternalGetInt(seed, null, null);

        /// <summary>
        /// Gets the next random integer of this algorithm given a seed.
        /// </summary>
        /// <param name="seed"> The <see langword="string"/> seed to use to produce the random integer. </param>
        /// <returns> The randomly generated integer. </returns>
        public static int GetInt(string seed) => InternalGetInt(Encoding.UTF8.GetBytes(seed), null, null);

        /// <summary>
        /// Gets the next random integer of this algorithm given the maximum value.
        /// </summary>
        /// <param name="maxValue"> The exclusive maximum value of the random integer. </param>
        /// <returns> The randomly generated integer. </returns>
        public static int GetInt(int maxValue) => InternalGetInt(null, null, maxValue);

        /// <summary>
        /// Gets the next random integer of this algorithm given a seed and the maximum value.
        /// </summary>
        /// <param name="seed"> The <see langword="byte"/>[] seed to use to produce the random integer. </param>
        /// <param name="maxValue"> The exclusive maximum value of the random integer. </param>
        /// <returns> The randomly generated integer. </returns>
        public static int GetInt(byte[] seed, int maxValue) => InternalGetInt(seed, null, maxValue);

        /// <summary>
        /// Gets the next random integer of this algorithm given a seed and the maximum value.
        /// </summary>
        /// <param name="seed"> The <see langword="string"/> seed to use to produce the random integer. </param>
        /// <param name="maxValue"> The exclusive maximum value of the random integer. </param>
        /// <returns> The randomly generated integer. </returns>
        public static int GetInt(string seed, int maxValue) => InternalGetInt(Encoding.UTF8.GetBytes(seed), null, maxValue);

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
        /// <param name="seed"> The <see langword="byte"/>[] seed to use to produce the random integer. </param>
        /// <param name="minValue"> The inclusive minimum value of the random integer. </param>
        /// <param name="maxValue"> The exclusive maximum value of the random integer. </param>
        /// <returns> The randomly generated integer. </returns>
        public static int GetInt(byte[] seed, int minValue, int maxValue) => InternalGetInt(seed, minValue, maxValue);

        /// <summary>
        /// Gets the next random integer of this algorithm given the a seed, as well as minimum and maximum values.
        /// </summary>
        /// <param name="seed"> The <see langword="string"/> seed to use to produce the random integer. </param>
        /// <param name="minValue"> The inclusive minimum value of the random integer. </param>
        /// <param name="maxValue"> The exclusive maximum value of the random integer. </param>
        /// <returns> The randomly generated integer. </returns>
        public static int GetInt(string seed, int minValue, int maxValue) => InternalGetInt(Encoding.UTF8.GetBytes(seed), minValue, maxValue);

        /// <summary>
        /// Gets the next random integer given all required parameters.
        /// </summary>
        /// <param name="seed"> The <see langword="byte"/>[] seed to use to produce the random integer. </param>
        /// <param name="minValue"> The inclusive minimum value of the random integer. </param>
        /// <param name="maxValue"> The exclusive maximum value of the random integer. </param>
        /// <returns> The randomly generated integer. </returns>
        private static int InternalGetInt(byte[] seed, int? minValue, int? maxValue) => GetInt(seed, minValue, maxValue, new T());

        /// <summary>
        /// Gets the next random integer given the <see cref="IDigest"/> hash function to use.
        /// </summary>
        /// <param name="seed"> The <see langword="byte"/>[] seed to use to produce the random integer. </param>
        /// <param name="minValue"> The inclusive minimum value of the random integer. </param>
        /// <param name="maxValue"> The exclusive maximum value of the random integer. </param>
        /// <param name="digest"> The <see cref="IDigest"/> to use to derive our random integer. </param>
        /// <returns> The randomly generated integer. </returns>
        private static int GetInt(byte[] seed, int? minValue, int? maxValue, IDigest digest)
        {
            AdvancedSecureRandom secureRandom = (seed == null ? new AdvancedSecureRandom(digest) : new AdvancedSecureRandom(digest, seed));

            if (minValue.HasValue && maxValue.HasValue)
                return secureRandom.Next(minValue.Value, maxValue.Value);
            else if (maxValue.HasValue)
                return secureRandom.Next(maxValue.Value);
            else
                return secureRandom.Next();
        }
    }
}