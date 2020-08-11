using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Android.App;
using Android.OS;
using Android.Runtime;
using Android.Support.Design.Widget;
using Android.Support.V7.App;
using Android.Support.V7.Widget;
using Android.Views;
using Android.Widget;

namespace SecureMessagingApp
{
    [Activity(Label = "@string/app_name", Theme = "@style/AppTheme.NoActionBar", MainLauncher = true)]
    public class MainActivity : AppCompatActivity
    {
        protected override void OnCreate(Bundle savedInstanceState)
        {
            base.OnCreate(savedInstanceState);
            Xamarin.Essentials.Platform.Init(this, savedInstanceState);
            SetContentView(Resource.Layout.activity_main);

            FindViewById<Button>(Resource.Id.btnEncrypt).Click += ClickEncrypt;
            FindViewById<Button>(Resource.Id.btnDecrypt).Click += ClickDecrypt;
        }

        public override bool OnCreateOptionsMenu(IMenu menu)
        {
            MenuInflater.Inflate(Resource.Menu.menu_main, menu);
            return true;
        }

        public override bool OnOptionsItemSelected(IMenuItem item)
        {
            int id = item.ItemId;
            if (id == Resource.Id.action_settings)
            {
                return true;
            }

            return base.OnOptionsItemSelected(item);
        }

        private void FabOnClick(object sender, EventArgs eventArgs)
        {
            View view = (View) sender;
            Snackbar.Make(view, "Replace with your own action", Snackbar.LengthLong)
                .SetAction("Action", (Android.Views.View.IOnClickListener)null).Show();
        }

        public override void OnRequestPermissionsResult(int requestCode, string[] permissions, [GeneratedEnum] Android.Content.PM.Permission[] grantResults)
        {
            Xamarin.Essentials.Platform.OnRequestPermissionsResult(requestCode, permissions, grantResults);

            base.OnRequestPermissionsResult(requestCode, permissions, grantResults);
        }
        private void ClickEncrypt(object sender, EventArgs eventArgs)
        {
            var pw = FindViewById<AppCompatEditText>(Resource.Id.txtPassword).Text;
            var mCount = long.Parse(FindViewById<AppCompatEditText>(Resource.Id.txtMessageCount).Text);
            var filepath = FindViewById<AppCompatEditText>(Resource.Id.txtFilePath).Text;
            var input = FindViewById<AppCompatEditText>(Resource.Id.txtInput).Text;

            try
            {
                FindViewById<AppCompatEditText>(Resource.Id.txtResult).Text = ByteStuff.ByteArrayToHexString(SecureMessager.SecureMessageEncrypt(
                    input,
                    pw,
                    mCount,
                    filepath));

                FindViewById<AppCompatEditText>(Resource.Id.txtNewMessageCount).Text = (mCount + FindViewById<AppCompatEditText>(Resource.Id.txtResult).Text.Length).ToString();
            }
            catch
            {
                FindViewById<AppCompatEditText>(Resource.Id.txtResult).Text = "Error: Could not convert";
                FindViewById<AppCompatEditText>(Resource.Id.txtMessageCount).Text = "0";
            }
        }
        private void ClickDecrypt(object sender, EventArgs eventArgs)
        {
            var pw = FindViewById<AppCompatEditText>(Resource.Id.txtPassword).Text;
            var mCount = long.Parse(FindViewById<AppCompatEditText>(Resource.Id.txtMessageCount).Text);
            var filepath = FindViewById<AppCompatEditText>(Resource.Id.txtFilePath).Text;
            var input = FindViewById<AppCompatEditText>(Resource.Id.txtInput).Text;

            try
            {
                FindViewById<AppCompatEditText>(Resource.Id.txtResult).Text = 
                new string(
                    SecureMessager.SecureMessageDecrypt(
                       ByteStuff.HexStringToByteArray(input),
                        pw,
                        mCount,
                        filepath));

                FindViewById<AppCompatEditText>(Resource.Id.txtNewMessageCount).Text = (mCount + FindViewById<AppCompatEditText>(Resource.Id.txtResult).Text.Length).ToString();
            }
            catch
            {
                FindViewById<AppCompatEditText>(Resource.Id.txtResult).Text = "Error: Could not convert";
                FindViewById<AppCompatEditText>(Resource.Id.txtMessageCount).Text = "0";
            }
        }




        public static class SecureMessager
        {
            public static char[] SecureMessageEncrypt(string messageString, string password, long messageCount, string filepath)
            {
                var output = SecureMessageFileMorph(messageString.ToArray(), true, password, messageCount, filepath);
                return output;
            }

            public static char[] SecureMessageDecrypt(char[] cryptoMessage, string password, long messageCount, string filepath)
            {
                var message = SecureMessageFileMorph(cryptoMessage, false, password, messageCount, filepath);
                return message;
            }

            // Get the AES encryption value of the password concat with messageCount. 
            //  Why? This gives us an unguessable but repeatable way to choose bytes from the source file to morph the message.
            //  The AES encryption gives us a 256 character encryption result. We turn this into Hex now it's 512 characters.
            //  We parse the hex into a big integer, now it's about 617 characters/digits.
            // Parse the encryption value into a long (one set of 18 digits at a time)
            //  if we get to the end of the big int, we wrap around which makes sure we don't use the exact same long step more than we need to.
            // Use the long to step into the file and get a byte
            // combine the next file byte with the next message byte to produce either the decrypt or the encrypt of the message
            public static char[] SecureMessageFileMorph(char[] cryptoMessage, bool encrypt, string password, long messageCount, string path)
            {
                int stepPosition = 0;
                int longIncrement = 18;
                var offset = AESEncryption.Encrypt(SHA2.GetSHA2(password + messageCount), password).ToArray();
                var offsetHexString = ByteStuff.ByteArrayToHexString(offset);
                string bi = BigInteger.Parse(
                    offsetHexString,
                    NumberStyles.AllowHexSpecifier).ToString();
                Stream fs;
                long length;
                if (path.Contains("http:") || path.Contains("https:"))
                {
                    string html = HTTPGet(path);
                    length = html.Length;
                    byte[] byteArray = Encoding.UTF8.GetBytes(html);
                    fs = new MemoryStream(byteArray);
                }
                else
                {
                    fs = File.OpenRead(path);
                    length = fs.Length;
                }
                long realIndex = long.Parse(bi.Substring(stepPosition, longIncrement));
                stepPosition += longIncrement;
                realIndex = realIndex % length;
                long count = 0;
                fs.Position = realIndex;
                Console.WriteLine(realIndex);
                char[] output = new char[cryptoMessage.Length];
                while (count < cryptoMessage.Length)
                {
                    byte read = (byte)fs.ReadByte();
                    if (read == 0)
                    { continue; }
                    if (encrypt)
                        output[count] = (char)(byte)(cryptoMessage[count] + read);
                    else
                        output[count] = (char)(byte)(cryptoMessage[count] - read);
                    count++;
                    //step the index by the next offset value in our AES key (stored in "bi"), 
                    //  both the file index starting point and each increment jump should be unpredictable without AES key.
                    long newStep = 0;
                    if (bi.Length >= stepPosition + longIncrement)
                    {
                        newStep = long.Parse(bi.Substring(stepPosition, longIncrement));
                        stepPosition += longIncrement;
                    }
                    else //need to wrap around the end.
                    {
                        string part1 = bi.Substring(stepPosition);
                        stepPosition = stepPosition + longIncrement - bi.Length;
                        string part2 = bi.Substring(0, stepPosition);
                        newStep = long.Parse(part1 + part2);
                    }

                    fs.Position = (fs.Position + newStep) % length;

                    Console.WriteLine(fs.Position);
                }
                fs.Close();
                return output;
            }
            // gets the file from the url
            public static string HTTPGet(string path)
            {
                string html = string.Empty;

                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(path);
                request.AutomaticDecompression = DecompressionMethods.GZip;
                ServicePointManager.Expect100Continue = true;
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls
                   | SecurityProtocolType.Tls11
                   | SecurityProtocolType.Tls12
                   | SecurityProtocolType.Ssl3;

                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                using (Stream stream = response.GetResponseStream())
                using (StreamReader reader = new StreamReader(stream))
                {
                    html = reader.ReadToEnd();
                }
                return html;
            }
        }
        //utility class to convert between hex strings and byte arrays
        public static class ByteStuff
        {
            public static string ByteArrayToHexString(char[] ba)
            {
                StringBuilder hex = new StringBuilder(ba.Length * 2);
                foreach (byte b in ba)
                    hex.AppendFormat("{0:x2}", b);
                return hex.ToString();
            }
            public static char[] HexStringToByteArray(string hex)
            {
                StringBuilder ba = new StringBuilder(hex.Length / 2);
                char[] output = new char[hex.Length / 2];
                for (int i = 0; i < hex.Length; i = i + 2)
                {
                    output[i / 2] = (char)Convert.ToUInt32(hex.Substring(i, 2), 16);
                }
                return output;
            }
        }
        // utility class that uses the .NET crypto SHA hashing function
        public static class SHA2
        {
            public static string GetSHA2(string input)
            {
                var alg = SHA512.Create();
                alg.ComputeHash(Encoding.UTF8.GetBytes(input));
                return BitConverter.ToString(alg.Hash);
            }
        }
        /// <summary>
        /// Utility class that handles encryption using .NET crypto libraries
        ///   this is just cobbled together from an example online.
        /// We don't need a "real" salt or IV because we don't rely on them to hide the results
        ///   in the above implementation, the file is the source of the entropy.
        ///   Salt protects the same password from producing the same encryption result, but 
        ///    our implemenation would need both same password and same file, making salt redundant.
        /// We can show in testing that the distribution of the AES encryption values creates sufficient
        ///    randomness for our purpose of stepping abritrarily through the bytes of the file.
        /// </summary>
        public static class AESEncryption
        {
            #region Static Functions

            /// <summary>
            /// Encrypts a string
            /// </summary>
            /// <param name="PlainText">Text to be encrypted</param>
            /// <param name="Password">Password to encrypt with</param>
            /// <param name="Salt">Salt to encrypt with</param>
            /// <param name="HashAlgorithm">Can be either SHA1 or MD5</param>
            /// <param name="PasswordIterations">Number of iterations to do</param>
            /// <param name="InitialVector">Needs to be 16 ASCII characters long</param>
            /// <param name="KeySize">Can be 128, 192, or 256</param>
            /// <returns>An encrypted string</returns>
            public static string Encrypt(string PlainText, string Password,
                string Salt = "Kosher", string HashAlgorithm = "SHA1",
                int PasswordIterations = 2, string InitialVector = "OFRna73m*aze01xY",
                int KeySize = 256)
            {
                if (string.IsNullOrEmpty(PlainText))
                    return "";
                byte[] InitialVectorBytes = Encoding.ASCII.GetBytes(InitialVector);
                byte[] SaltValueBytes = Encoding.ASCII.GetBytes(Salt);
                byte[] PlainTextBytes = Encoding.UTF8.GetBytes(PlainText);
                PasswordDeriveBytes DerivedPassword = new PasswordDeriveBytes(Password, SaltValueBytes, HashAlgorithm, PasswordIterations);
                byte[] KeyBytes = DerivedPassword.GetBytes(KeySize / 8);
                RijndaelManaged SymmetricKey = new RijndaelManaged();
                SymmetricKey.Mode = CipherMode.CBC;
                byte[] CipherTextBytes = null;
                using (ICryptoTransform Encryptor = SymmetricKey.CreateEncryptor(KeyBytes, InitialVectorBytes))
                {
                    using (MemoryStream MemStream = new MemoryStream())
                    {
                        using (CryptoStream CryptoStream = new CryptoStream(MemStream, Encryptor, CryptoStreamMode.Write))
                        {
                            CryptoStream.Write(PlainTextBytes, 0, PlainTextBytes.Length);
                            CryptoStream.FlushFinalBlock();
                            CipherTextBytes = MemStream.ToArray();
                            MemStream.Close();
                            CryptoStream.Close();
                        }
                    }
                }
                SymmetricKey.Clear();
                return Convert.ToBase64String(CipherTextBytes);
            }

            /// Decrypts a string. We don't use this function in our implementation.
            public static string Decrypt(string CipherText, string Password,
                string Salt = "Kosher", string HashAlgorithm = "SHA1",
                int PasswordIterations = 2, string InitialVector = "OFRna73m*aze01xY",
                int KeySize = 256)
            {
                if (string.IsNullOrEmpty(CipherText))
                    return "";
                byte[] InitialVectorBytes = Encoding.ASCII.GetBytes(InitialVector);
                byte[] SaltValueBytes = Encoding.ASCII.GetBytes(Salt);
                byte[] CipherTextBytes = Convert.FromBase64String(CipherText);
                PasswordDeriveBytes DerivedPassword = new PasswordDeriveBytes(Password, SaltValueBytes, HashAlgorithm, PasswordIterations);
                byte[] KeyBytes = DerivedPassword.GetBytes(KeySize / 8);
                RijndaelManaged SymmetricKey = new RijndaelManaged();
                SymmetricKey.Mode = CipherMode.CBC;
                byte[] PlainTextBytes = new byte[CipherTextBytes.Length];
                int ByteCount = 0;
                using (ICryptoTransform Decryptor = SymmetricKey.CreateDecryptor(KeyBytes, InitialVectorBytes))
                {
                    using (MemoryStream MemStream = new MemoryStream(CipherTextBytes))
                    {
                        using (CryptoStream CryptoStream = new CryptoStream(MemStream, Decryptor, CryptoStreamMode.Read))
                        {

                            ByteCount = CryptoStream.Read(PlainTextBytes, 0, PlainTextBytes.Length);
                            MemStream.Close();
                            CryptoStream.Close();
                        }
                    }
                }
                SymmetricKey.Clear();
                return Encoding.UTF8.GetString(PlainTextBytes, 0, ByteCount);
            }

            #endregion
        }
    }
}
