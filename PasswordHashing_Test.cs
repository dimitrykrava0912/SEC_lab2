using System;
using Xunit;
using IIG.PasswordHashingUtils;

namespace lab2
{
    public class PasswordHashing_Test
    {
        const string password = "password";
        const string passwordCaseSensitive = "PaSsWoRd";

        const string salt = "salt";
        const uint _adlerMod32 = 123456789;

        [Fact]
        public void Test_GetHash()
        {
            Assert.Equal(PasswordHasher.GetHash(password), PasswordHasher.GetHash(password));
        }

        [Fact]
        public void Test_GetHashCaseSensitive()
        {
            Assert.NotEqual(PasswordHasher.GetHash(password), PasswordHasher.GetHash(passwordCaseSensitive));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void Test_GetHashFromEmptySalt(string salt)
        {
            Assert.NotNull(PasswordHasher.GetHash(password, salt));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void Test_GetHashFromEmptyPassword(string password)
        {
            Assert.NotNull(PasswordHasher.GetHash(password));
        }
        
        [Fact]
        public void Test_PasswordSpesialSymbolsTest()
        {
            string specialSymbols = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

            Assert.NotNull(PasswordHasher.GetHash(specialSymbols));
        }

        [Fact]
        public void Test_SaltSpesialSymbolsTest()
        {
            string specialSymbols = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

            Assert.NotNull(PasswordHasher.GetHash(password, specialSymbols));
        }

        private string generateLongString(int length)
        {
            string s = "";

            for (int i = 0; i < length; i++)
            {
                s += "q";
            }

            return s;
        }

        [Theory]
        [InlineData(100)]
        [InlineData(2048)]
        [InlineData(65535)]
        [InlineData(131070)]
        public void Test_PasswordBoundaryValue(int length)
        {
            string pass = generateLongString(length);

            Assert.NotNull(PasswordHasher.GetHash(pass));
        }

        [Theory]
        [InlineData(100)]
        [InlineData(2048)]
        [InlineData(65535)]
        [InlineData(131070)]
        public void Test_SaltBoundaryValue(int length)
        {
            string salt = generateLongString(length);

            Assert.NotNull(PasswordHasher.GetHash(password, salt));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(2048)]
        [InlineData(65535)]
        [InlineData(131070)]
        [InlineData(4294967296)]
        public void Test__adlerMod32BoundaryValue(uint value)
        {
            Assert.NotNull(PasswordHasher.GetHash(password, salt, value));
        }

        [Fact]
        public void Test_InitMethod()
        {
            string hashWithPredefinedSaltAnd_adlerMod32 = PasswordHasher.GetHash(password);

            string hashWithCustomSaltAnd_adlerMod32_WithoutInit = PasswordHasher.GetHash(password, salt, _adlerMod32);

            PasswordHasher.Init(salt, _adlerMod32);
            string hashWithCustomSaltAnd_adlerMod32 = PasswordHasher.GetHash(password);

            Assert.NotEqual(hashWithCustomSaltAnd_adlerMod32, hashWithPredefinedSaltAnd_adlerMod32);
            Assert.Equal(hashWithCustomSaltAnd_adlerMod32_WithoutInit, hashWithCustomSaltAnd_adlerMod32);
        }
    }
}