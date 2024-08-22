    public static class DecryptLogger
    {
        private static readonly string JsonLogDirectory = "JsonLogs";

        public static void PrefixE007(object backRequest, object bResponse)
        {
            var responseType = bResponse.GetType();

            var responseDataField = responseType.GetField("responseData");
            var responseDataLengthField = responseType.GetField("responseDataLength");

            byte[] responseData = (byte[])responseDataField.GetValue(bResponse);
            int responseDataLength = (int)responseDataLengthField.GetValue(bResponse);

            if (responseData != null)
            {
                // nun
            }
        }

        public static void PrefixE002(byte[] cipherText, int cipherBytesLength, byte[] Key, byte[] IV)
        {
            try
            {
                byte[] decryptedData = DecryptData(cipherText, cipherBytesLength, Key, IV);
                string decompressedData = DecompressData(decryptedData);

                //json,key,iv
                var logEntry = new
                {
                    Timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                    Key = BitConverter.ToString(Key).Replace("-", ""),
                    IV = BitConverter.ToString(IV).Replace("-", ""),
                    DecompressedData = decompressedData
                };

                SaveLogToJsonFile(logEntry);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during decryption or decompression: {ex.Message}");
            }
        }

        private static byte[] DecryptData(byte[] cipherText, int cipherBytesLength, byte[] Key, byte[] IV)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Padding = PaddingMode.Zeros;
                aes.Key = Key;
                aes.IV = IV;

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(cipherText, 0, cipherBytesLength);
                        cryptoStream.FlushFinalBlock();
                    }

                    return memoryStream.ToArray();
                }
            }
        }

        private static string DecompressData(byte[] data)
        {
            ZStream zstream = new ZStream();
            zstream.inflateInit();

            byte[] buffer = new byte[4096];
            zstream.next_in = data;
            zstream.next_in_index = 0;
            zstream.avail_in = data.Length;

            using (MemoryStream memoryStream = new MemoryStream())
            {
                int status;
                do
                {
                    zstream.next_out = buffer;
                    zstream.next_out_index = 0;
                    zstream.avail_out = buffer.Length;
                    status = zstream.inflate(ZlibConst.Z_NO_FLUSH);

                    if (status != ZlibConst.Z_OK && status != ZlibConst.Z_STREAM_END && status != ZlibConst.Z_BUF_ERROR)
                    {
                        throw new InvalidOperationException($"Zlib inflate failed with status: {status}");
                    }

                    memoryStream.Write(buffer, 0, buffer.Length - zstream.avail_out);
                }
                while (status != ZlibConst.Z_STREAM_END && zstream.avail_in > 0);

                zstream.inflateEnd();
                return Encoding.UTF8.GetString(memoryStream.ToArray());
            }
        }

        private static void SaveLogToJsonFile(object logEntry)
        {
            try
            {
                Directory.CreateDirectory(JsonLogDirectory);

                // timestamp
                string fileName = $"{DateTime.Now:yyyy-MM-dd_HH-mm-ss-fff}.json";
                string filePath = Path.Combine(JsonLogDirectory, fileName);

                // serializee
                string jsonLog = JsonConvert.SerializeObject(logEntry, Formatting.Indented);
                File.WriteAllText(filePath, jsonLog);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to save JSON log: {ex.Message}");
            }
        }
    }

    public static class HarmonyPatcher
    {
        public static void ApplyPatches()
        {
            var harmony = new Harmony("com.eft.decryptlogger");

            // Hook into \uE002 
            var decryptClass = AccessTools.TypeByName("\uE2E3");
            var methodE002 = AccessTools.Method(decryptClass, "\uE002");
            if (methodE002 != null)
            {
                var prefixE002 = typeof(DecryptLogger).GetMethod(nameof(DecryptLogger.PrefixE002), BindingFlags.Static | BindingFlags.Public);
                harmony.Patch(methodE002, new HarmonyMethod(prefixE002));
            }

            // Hook into \uE007 
            var methodE007 = AccessTools.Method(decryptClass, "\uE007");
            if (methodE007 != null)
            {
                var prefixE007 = typeof(DecryptLogger).GetMethod(nameof(DecryptLogger.PrefixE007), BindingFlags.Static | BindingFlags.Public);
                harmony.Patch(methodE007, new HarmonyMethod(prefixE007));
            }

            Console.WriteLine("All hooks successfully applied.");
        }
    }

    public static class ZlibConst
    {
        public const int Z_NO_FLUSH = 0;
        public const int Z_FINISH = 4;
        public const int Z_STREAM_END = 1;
        public const int Z_OK = 0;
        public const int Z_BUF_ERROR = -5;
    }

