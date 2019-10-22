using Org.BouncyCastle.Crypto;
using System.Text;

namespace Hope.Random.Numbers.Abstract
{
    /// <summary>
    /// Base class used for generating random doubles.
    /// </summary>
    /// <typeparam name="T"> The hash algorithm to use to generate our random doubles. </typeparam>
    public abstract class SecureRandomDoubleBase<T> where T : IDigest, new()
    {
        /// <summary>
        /// Gets the next random double of this algorithm.
        /// </summary>
        /// <returns> The randomly generated double. </returns>
        public static double GetDouble() => InternalGetDouble(null, null, null);

        /// <summary>
        /// Gets the next random double of this algorithm given a seed.
        /// </summary>
        /// <param name="seed"> The <see langword="byte"/>[] seed to use to produce the random double. </param>
        /// <returns> The randomly generated double. </returns>
        public static double GetDouble(byte[] seed) => InternalGetDouble(seed, null, null);

        /// <summary>
        /// Gets the next random double of this algorithm given a seed.
        /// </summary>
        /// <param name="seed"> The <see langword="string"/> seed to use to produce the random double. </param>
        /// <returns> The randomly generated double. </returns>
        public static double GetDouble(string seed) => InternalGetDouble(Encoding.UTF8.GetBytes(seed), null, null);

        /// <summary>
        /// Gets the next random double of this algorithm given the maximum value.
        /// </summary>
        /// <param name="maxValue"> The exclusive maximum value of the random double. </param>
        /// <returns> The randomly generated double. </returns>
        public static double GetDouble(double maxValue) => InternalGetDouble(null, null, maxValue);

        /// <summary>
        /// Gets the next random double of this algorithm given a seed and the maximum value.
        /// </summary>
        /// <param name="seed"> The <see langword="byte"/>[] seed to use to produce the random double. </param>
        /// <param name="maxValue"> The exclusive maximum value of the random double. </param>
        /// <returns> The randomly generated double. </returns>
        public static double GetDouble(byte[] seed, double maxValue) => InternalGetDouble(seed, null, maxValue);

        /// <summary>
        /// Gets the next random double of this algorithm given a seed and the maximum value.
        /// </summary>
        /// <param name="seed"> The <see langword="string"/> seed to use to produce the random double. </param>
        /// <param name="maxValue"> The exclusive maximum value of the random double. </param>
        /// <returns> The randomly generated double. </returns>
        public static double GetDouble(string seed, double maxValue) => InternalGetDouble(Encoding.UTF8.GetBytes(seed), null, maxValue);

        /// <summary>
        /// Gets the next random double of this algorithm given the minimum and maximum value.
        /// </summary>
        /// <param name="minValue"> The inclusive minimum value of the random double. </param>
        /// <param name="maxValue"> The exclusive maximum value of the random double. </param>
        /// <returns> The randomly generated double. </returns>
        public static double GetDouble(double minValue, double maxValue) => InternalGetDouble(null, minValue, maxValue);

        /// <summary>
        /// Gets the next random double of this algorithm given the a seed, as well as minimum and maximum values.
        /// </summary>
        /// <param name="seed"> The <see langword="byte"/>[] seed to use to produce the random double. </param>
        /// <param name="minValue"> The inclusive minimum value of the random double. </param>
        /// <param name="maxValue"> The exclusive maximum value of the random double. </param>
        /// <returns> The randomly generated double. </returns>
        public static double GetDouble(byte[] seed, double minValue, double maxValue) => InternalGetDouble(seed, minValue, maxValue);

        /// <summary>
        /// Gets the next random double of this algorithm given the a seed, as well as minimum and maximum values.
        /// </summary>
        /// <param name="seed"> The <see langword="string"/> seed to use to produce the random double. </param>
        /// <param name="minValue"> The inclusive minimum value of the random double. </param>
        /// <param name="maxValue"> The exclusive maximum value of the random double. </param>
        /// <returns> The randomly generated double. </returns>
        public static double GetDouble(string seed, double minValue, double maxValue) => InternalGetDouble(Encoding.UTF8.GetBytes(seed), minValue, maxValue);

        /// <summary>
        /// Gets the next random double given all required parameters.
        /// </summary>
        /// <param name="seed"> The <see langword="byte"/>[] seed to use to produce the random double. </param>
        /// <param name="minValue"> The inclusive minimum value of the random double. </param>
        /// <param name="maxValue"> The exclusive maximum value of the random double. </param>
        /// <returns> The randomly generated double. </returns>
        private static double InternalGetDouble(byte[] seed, double? minValue, double? maxValue) => InternalGetDouble(seed, minValue, maxValue, new T());

        /// <summary>
        /// Gets the next random double given the <see cref="IDigest"/> hash function to use.
        /// </summary>
        /// <param name="seed"> The <see langword="byte"/>[] seed to use to produce the random double. </param>
        /// <param name="minValue"> The inclusive minimum value of the random double. </param>
        /// <param name="maxValue"> The exclusive maximum value of the random double. </param>
        /// <param name="digest"> The <see cref="IDigest"/> to use to derive our random double. </param>
        /// <returns> The randomly generated double. </returns>
        private static double InternalGetDouble(byte[] seed, double? minValue, double? maxValue, IDigest digest)
        {
            AdvancedSecureRandom secureRandom = (seed == null ? new AdvancedSecureRandom(digest) : new AdvancedSecureRandom(digest, seed));

            if (minValue.HasValue && maxValue.HasValue)
            {
                return secureRandom.Next((int)minValue.Value, (int)maxValue.Value - 1) + secureRandom.NextDouble();
            }
            else if (maxValue.HasValue)
            {
                return secureRandom.Next((int)maxValue.Value - 1) + secureRandom.NextDouble();
            }
            else
            {
                return secureRandom.NextDouble();
            }
        }
    }
}
