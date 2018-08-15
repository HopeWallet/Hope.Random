namespace RandomNet.Secure
{
    /// <summary>
    /// Interface which classes can inherit if they want to use a class instance as a seed.
    /// </summary>
    public interface IRandomSeed
    {
        /// <summary>
        /// The seed of this object.
        /// </summary>
        byte[] Seed { get; }
    }
}