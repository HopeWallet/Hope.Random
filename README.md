# Hope.Random

Hope.Random is a simple random data library which features fast random data generation as well as cryptographically secure random generation with the help of the Bouncy Castle Crypto library.

## Installation

The required dlls for the Hope.Random library are located in the [Hope.Random releases](https://github.com/HopeWallet/Hope.Random/releases). Download the latest Hope.Random zip file, and add all required dlls to your project references.

## Usage

Hope.Random is a very simple library to use. Due to this fact, it is not very extendible. However, there are some classes which allow for more advanced usage.

### Simple Usage

Currently, the simple random generation is split into three random generation sections: random bytes, random strings, and random integers.

Each random category is split into both ```Secure``` and ```Fast``` sections.

You can generate random data using the following code.

```c#
// Secure random integers
int randomInt = RandomInt.Secure.SHA3.GetInt();
int seededRandomInt = RandomInt.Secure.SHA3("4v98q9eguidsg958"); // Will always generate the same int value

// Fast random
int fastRandom = RandomInt.Fast.GetInt(0, 101); // Generates a nonsecure random int between 0 and 100.
```

The methods are the same for ```RandomBytes``` and ```RandomString```.

You may notice there are a variety of different secure classes which generate random data. Each class will produce different random data even if the seed is the same.

```c#
// Each random byte generation is cryptographically secure.
// However, each will produce different results while the seed and byte data length remains the same.
// They all use different hash algorithms to produce the random data
RandomBytes.Secure.SHA3.GetBytes("my seed", 25);
RandomBytes.Secure.Blake2.GetBytes("my seed", 25);
RandomBytes.Secure.MD5.GetBytes("my seed", 25);
RandomBytes.Secure.SHA1.GetBytes("my seed", 25);
RandomBytes.Secure.SHA512.GetBytes("my seed", 25);
RandomBytes.Secure.Shake.GetBytes("my seed", 25);
```

Some classes which generate random data are more secure than others. For example, the ```SHA3``` variants are more secure than ```MD5```, while being a bit slower with the random generation.

Take a look at the classes inside the [Hope.Random.Tests](https://github.com/HopeWallet/Hope.Random/tree/master/Hope.Random/Hope.Random.Tests) folder for more examples on random data generation.

### Advanced Usage

One annoyance I found with the ```SecureRandom``` class from the Bouncy Castle Crypto library was that it did not allow me to specify my hash algorithm for my random data generation. To circumvent this I implemented a new wrapper class over ```SecureRandom```, called the ```AdvancedSecureRandom```.

The ```AdvancedSecureRandom``` allows for any ```IDigest``` to use for the random data generation, as well as any arbitrary number of objects to use as a seed. You can input many different variables to calculate the seed for the random data generation. An integer, boolean, string, byte[], etc...

```c#
// SHA3-512 algorithm used for random data generation.
AdvancedSecureRandom secureRandom = new AdvancedSecureRandom(new Sha3Digest(512));
int randomInt = secureRandom.Next();

// Keccak-512 algorithm used for random data generation, as well as some extra seed data.
// Any AdvancedSecureRandom with this seed data and the same algorithm will produce the same results consistently.
AdvancedSecureRandom secureRandom = new AdvancedSecureRandom(new Keccak(512), "seed1", "seed2", 581832);
int randomInt = secureRandom.Next();
```

See the [Hope.Random.Tests](https://github.com/HopeWallet/Hope.Random/tree/master/Hope.Random/Hope.Random.Tests) folder for more ```AdvancedSecureRandom``` tests.

## Final Words

This is a library of utility classes that were created for use in the Hope Ethereum wallet. This library won't likely get udated too much unless there are any glaring issues anywhere that haven't been discovered. If you encounter any problems, post an issue and support will gladly be provided!
