using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.Lms;
using Org.BouncyCastle.Security;
using System;
using System.Data.SQLite;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;
using System.Security.Cryptography;
using System.Text;
using static Org.BouncyCastle.Bcpg.Attr.ImageAttrib;

namespace Leashmore
{
    public partial class ENV
    {
        protected static byte[] encryption_key = new byte[16];
        protected static byte[] verification_key = new byte[16];
        protected static byte[] decrypted_tag = new byte[32];
        public static string selected_id;
        private static string[] Note_ids;
        public const string SQLiteconnectionString = "Data Source=encrypted_database.db;Version=3;";
        public static long selected_row;

        static void Main()
        {
            Console.WriteLine();
            create_required_tables_if_not_exist();
            string encr_bash_of_mp = get_encr_hash_of_password_from_db();
            if (encr_bash_of_mp == "-1")
                set_password();
            else
                ask_user_for_password(encr_bash_of_mp);

            DisplayMenu();
        }

        private static void DisplayMenu()
        {
            while (true)
            {
                Console.WriteLine("1. Add Note");
                Console.WriteLine("2. View Note");
                Console.WriteLine("3. Delete Note");
                Console.WriteLine("4. Exit");
                Console.WriteLine();
                Console.Write("Enter your choice [1-4]: ");
                string choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        AddNote();
                        break;
                    case "2":
                        ViewNote();
                        break;
                    case "3":
                        DeleteNote();
                        break;
                    case "4":
                        Exit();
                        break;
                    default:
                        Console.WriteLine("Invalid choice. Please enter a number between 1 and 4.");
                        break;
                }

                Console.WriteLine(); // Add a newline for better readability
            }
        }

        private static void Exit()
        {
            for (int i = 0; i < 16; i++)
            {
                encryption_key[i] = 0;
                verification_key[i] = 0;
            }
            Environment.Exit(0);
        }

        private static void show_message_in_console(string mssg)
        {
            Console.WriteLine();
            Console.WriteLine(mssg);
            Console.WriteLine();
        }

        private static void show_two_line_message_in_console(string line1, string line2)
        {
            Console.WriteLine();
            Console.WriteLine(line1);
            Console.WriteLine();
            Console.WriteLine(line2);
            Console.WriteLine();
        }

        private static void ViewNote()
        {
            list_stored_records("Choose Note to View");
            int snmbr = get_slot_number("View Note N");
            if (snmbr == -1)
                show_message_in_console("Operation Was Cancelled By User");
            else
            {
                try
                {
                    string record_id = AccessArrayElement(snmbr);
                    if (record_id.Length > 9)
                    {
                        string decr_ttl = Decrypt_string_with_aes_in_cbc(Extract_value_from_record("Note", record_id, "Title"));
                        byte[] input = Encoding.Unicode.GetBytes(decr_ttl);
                        if (CalculateHMACSHA256(input).AsSpan().SequenceEqual(decrypted_tag))
                        {
                            Console.WriteLine();
                            Console.WriteLine("Title: " + decr_ttl);
                            Console.WriteLine();
                        }
                        else
                        {
                            
                            Console.ForegroundColor = ConsoleColor.Red;
                            show_message_in_console("Integrity Verification Failed");
                            Console.WriteLine();
                            Console.WriteLine("Title: " + decr_ttl);
                            Console.WriteLine();
                            Console.ForegroundColor = ConsoleColor.White;
                        }

                        string decr_cnt = Decrypt_string_with_aes_in_cbc(Extract_value_from_record("Note", record_id, "Content"));
                        byte[] input1 = Encoding.Unicode.GetBytes(decr_cnt);
                        if (CalculateHMACSHA256(input1).AsSpan().SequenceEqual(decrypted_tag))
                        {
                            Console.WriteLine();
                            Console.WriteLine("Content: " + decr_cnt);
                            Console.WriteLine();
                        }
                        else
                        {

                            Console.ForegroundColor = ConsoleColor.Red;
                            show_message_in_console("Integrity Verification Failed");
                            Console.WriteLine();
                            Console.WriteLine("Content: " + decr_cnt);
                            Console.WriteLine();
                            Console.ForegroundColor = ConsoleColor.White;
                        }
                    }
                }
                catch (IndexOutOfRangeException ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
                catch (FormatException ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }
        }

        private static void DeleteNote()
        {
            list_stored_records("Choose Note to Delete");
            int snmbr = get_slot_number("Delete Note N");
            if (snmbr == -1)
                show_message_in_console("Operation Was Cancelled By User");
            else
            {
                try
                {
                    string record_id = AccessArrayElement(snmbr);
                    if (record_id.Length > 9)
                        if (DeleteRecord("Note", record_id))
                        {
                            show_message_in_console("Record Deleted Successfully");
                        }
                }
                catch (IndexOutOfRangeException ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
                catch (FormatException ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }
        }

        private static string AccessArrayElement(int index)
        {
            if (index < 0 || (index - 1) >= Note_ids.Length)
            {
                throw new IndexOutOfRangeException("Selected Index Is Out Of Bounds.");
            }

            return Note_ids[index - 1];
        }

        private static string Extract_value_from_record(string table_name, string Record_id, string column_name)
        {
            string resultPaidGigs = string.Empty;

            using (SQLiteConnection connection = new SQLiteConnection(SQLiteconnectionString))
            {
                connection.Open();
                string query = $"SELECT {column_name} FROM {table_name} WHERE Rec_id = @Record_id";

                using (SQLiteCommand command = new SQLiteCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Record_id", Record_id);

                    using (SQLiteDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            resultPaidGigs = reader[column_name].ToString();
                        }
                    }
                }
                connection.Close();
            }
            return resultPaidGigs;
        }

        private static void AddNote()
        {
            Console.WriteLine();
            Console.Write("Enter Note Title: ");
            string title = Console.ReadLine();
            Console.Write("Enter Note Content: ");
            string content = Console.ReadLine();
            AddWNote(title, content);
        }

        private static void list_stored_records(string mssg)
        {
            // Create a List to store Rec_id values
            List<string> recIdsList = new List<string>();
            show_message_in_console(mssg);
            int i = 1;
            using (SQLiteConnection connection = new SQLiteConnection(SQLiteconnectionString))
            {
                connection.Open();

                // Assuming Worker is your table name
                string query = "SELECT Rec_id, Title FROM Note";

                using (SQLiteCommand command = new SQLiteCommand(query, connection))
                {
                    using (SQLiteDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            // Extracting information
                            string recId = reader["Rec_id"].ToString();
                            recIdsList.Add(recId);
                            Console.WriteLine($"[{i}] {Decrypt_string_with_aes_in_cbc(reader["Title"].ToString())}");
                            i++;
                        }
                    }
                }

                connection.Close();
            }
            Console.WriteLine("[c] Cancel");
            Note_ids = recIdsList.ToArray();
        }

        private static int get_slot_number(string what_to_do)
        {
            Console.WriteLine();
            Console.Write(what_to_do);
            string input = Console.ReadLine();

            if (input.ToLower() == "c")
            {
                return -1;
            }

            if (int.TryParse(input, out int result))
            {
                return result;
            }
            else
            {
                Console.WriteLine("Invalid Input. Please, Enter a Valid Value.");
                Console.WriteLine();
                return get_slot_number(what_to_do); // Recursive call until a valid integer is entered
            }
        }

        private static void set_password()
        {
            Console.Write("Set Password: ");
            string user_password = Console.ReadLine();

            Console.Clear();
            Console.Write("Setting Password...");
            string hashed_password = HashStringWithSHA512(user_password, 4 * CalculateAsciiSum(HashStringWithSHA512(user_password, 500)));
            byte[] source = StringToByteArray(hashed_password);
            for (int i = 0; i < 16; i++)
            {
                encryption_key[i] = source[i];
                verification_key[i] = source[i + 16];
            }
            byte[] to_be_hmaced = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                to_be_hmaced[i] = source[i + 32];
            }

            Console.Clear();
            using (SQLiteConnection connection = new SQLiteConnection(SQLiteconnectionString))
            {
                connection.Open();

                try
                {
                    string query = $"INSERT INTO Unlock (Rec_id, Encrypted_hash_of_the_password) VALUES (1, '" + Encrypt_hash_with_aes_in_cbc(CalculateHMACSHA256(to_be_hmaced)) + "')";

                    using (SQLiteCommand command = new SQLiteCommand(query, connection))
                    {
                        command.ExecuteNonQuery();
                        show_message_in_console("Password Set Successfully");
                    }
                }
                catch (Exception ex)
                {
                    show_two_line_message_in_console("Something went wrong with the database", $"Error: {ex.Message}");
                }
                finally
                {
                    connection.Close();
                }
            }

        }

        private static void ask_user_for_password(string encr_bash_of_mp)
        {
            Console.Write("Enter Your Password: ");
            string user_password = Console.ReadLine();

            Console.Clear();
            Console.Write("Unlocking Software...");
            string hashed_password = HashStringWithSHA512(user_password, 4 * CalculateAsciiSum(HashStringWithSHA512(user_password, 500)));
            byte[] source = StringToByteArray(hashed_password);
            for (int i = 0; i < 16; i++)
            {
                encryption_key[i] = source[i];
                verification_key[i] = source[i + 16];
            }
            byte[] to_be_hmaced = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                to_be_hmaced[i] = source[i + 32];
            }
            Console.Clear();
            if (!Decrypt_hash_with_aes_in_cbc(encr_bash_of_mp).SequenceEqual(CalculateHMACSHA256(to_be_hmaced)))
            {
                show_two_line_message_in_console("Wrong Password", "Please, Try Again");
                ask_user_for_password(encr_bash_of_mp);
            }
            else
                show_message_in_console("Software Unlocked Successfully");
        }

        private static string get_encr_hash_of_password_from_db()
        {
            StringBuilder enc_hash_to_ret = new StringBuilder();
            using (SQLiteConnection connection = new SQLiteConnection(SQLiteconnectionString))
            {
                connection.Open();
                int recId = 1;
                string query = $"SELECT * FROM Unlock WHERE Rec_id = {recId}";

                using (SQLiteCommand command = new SQLiteCommand(query, connection))
                {
                    using (SQLiteDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            // Record found, you can access the values using reader["ColumnName"]
                            int foundRecId = reader.GetInt32(reader.GetOrdinal("Rec_id"));
                            enc_hash_to_ret.Append(reader.GetString(reader.GetOrdinal("Encrypted_hash_of_the_password")));
                        }
                        else
                        {
                            enc_hash_to_ret.Append("-1");
                        }
                    }
                }

                connection.Close();
            }
            return enc_hash_to_ret.ToString();
        }

        public static bool CheckIfRecordExists(string recId, string table)
        {
            using (SQLiteConnection connection = new SQLiteConnection(SQLiteconnectionString))
            {
                connection.Open();

                try
                {
                    string query = $"SELECT 1 FROM {table} WHERE Rec_id = '{recId}' LIMIT 1";

                    using (SQLiteCommand command = new SQLiteCommand(query, connection))
                    {
                        object result = command.ExecuteScalar();
                        return result != null && result != DBNull.Value;
                    }
                }
                catch (Exception ex)
                {
                    return false;
                }
                finally
                {
                    connection.Close();
                }
            }
        }

        private static void create_required_tables_if_not_exist()
        {
            using (SQLiteConnection connection = new SQLiteConnection(SQLiteconnectionString))
            {
                connection.Open();

                CreateTableIfNotExist(connection, "Unlock", "Rec_id INTEGER, Encrypted_hash_of_the_password TEXT");
                CreateTableIfNotExist(connection, "Note", "Rec_id TEXT, Title Text, Content Text");

                connection.Close();
            }
        }

        private static string GenerateRandomString(int length)
        {
            const string allowedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] randomBytes = new byte[length];
                rng.GetBytes(randomBytes);

                char[] chars = new char[length];
                for (int i = 0; i < length; i++)
                {
                    int index = randomBytes[i] % allowedChars.Length;
                    chars[i] = allowedChars[index];
                }

                return new string(chars);
            }
        }
        static void AddWNote(string title, string content)
        {
            string recId = GenerateRandomString(10); // Generate random ID
            while (CheckIfRecordExists(recId, "Note") == true) // Check if the record with that ID is already in the database. If true, then keep generating new IDs until DB tells that record with such ID isn't present
                recId = GenerateRandomString(14); // If record with the generated ID already exists, then generate new ID and check again
            try
            {
                using (SQLiteConnection connection = new SQLiteConnection(SQLiteconnectionString))
                {
                    connection.Open();

                    string commandText = $@"INSERT INTO Note 
                                       (Rec_id, Title, Content) 
                                       VALUES 
                                       (@RecId, @Title, @Content)";

                    using (SQLiteCommand command = new SQLiteCommand(commandText, connection))
                    {
                        // Add parameters to the command
                        command.Parameters.AddWithValue("@RecId", recId);
                        command.Parameters.AddWithValue("@Title", Encrypt_string_with_aes_in_cbc(title));
                        command.Parameters.AddWithValue("@Content", Encrypt_string_with_aes_in_cbc(content));

                        // Execute the command
                        int rowsAffected = command.ExecuteNonQuery();

                        if (rowsAffected > 0)
                        {
                            show_message_in_console("Record Added Successfully!");
                        }
                        else
                        {
                            show_two_line_message_in_console("Failed to Add Record", "Please, Try Again");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                show_two_line_message_in_console("Something went wrong with the database", $"Error: {ex.Message}");
            }
        }

    private static bool DeleteRecord(string table, string id)
        {
            bool rec_deltd = false;
            using (SQLiteConnection connection = new SQLiteConnection(SQLiteconnectionString))
            {
                connection.Open();

                using (SQLiteCommand command = new SQLiteCommand(connection))
                {
                    // Construct the DELETE statement
                    command.CommandText = $"DELETE FROM {table} WHERE Rec_id = @id";
                    command.Parameters.AddWithValue("@id", id);

                    try
                    {
                        // Execute the DELETE statement
                        int rowsAffected = command.ExecuteNonQuery();

                        if (rowsAffected > 0)
                        {
                            rec_deltd = true;
                        }
                        else
                        {
                            show_two_line_message_in_console("Failed to Delete Record", $"Record \"{id}\" isn't found");
                        }
                    }
                    catch (Exception ex)
                    {
                        show_two_line_message_in_console($"Failed to Delete Record \"{id}\"", ex.Message);
                    }
                }
                connection.Close();
            }
            return rec_deltd;
        }

        private static void CreateTableIfNotExist(SQLiteConnection connection, string tableName, string columns)
        {
            using (SQLiteCommand command = new SQLiteCommand($"CREATE TABLE IF NOT EXISTS {tableName} ({columns});", connection))
            {
                command.ExecuteNonQuery();
            }
        }

        private static byte[] GenerateRandomByteArray(int length)
        {
            byte[] randomBytes = new byte[length];

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }

            return randomBytes;
        }

        public static string Encrypt_string_with_aes_in_cbc(string plaintext)
        {
            byte[] input = Encoding.Unicode.GetBytes(plaintext);
            byte[] iv = GenerateRandomByteArray(16);
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/CBC/PKCS7Padding");
            cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", encryption_key), iv));

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CipherStream cipherStream = new CipherStream(memoryStream, null, cipher))
                {
                    cipherStream.Write(input, 0, input.Length);
                }

                return Encrypt_hash_with_aes_in_cbc(CalculateHMACSHA256(input)) + BitConverter.ToString(EncryptAES(iv)).Replace("-", "") + BitConverter.ToString(memoryStream.ToArray()).Replace("-", "");
            }
        }

        private static string Decrypt_string_with_aes_in_cbc(string ciphertext)
        {
            try
            {
                decrypted_tag = Decrypt_hash_with_aes_in_cbc(ciphertext.Substring(0, 96));
                byte[] encrypted_iv = StringToByteArray(ciphertext.Substring(96, 32));
                byte[] iv = DecryptAES(encrypted_iv);
                byte[] input = StringToByteArray(ciphertext.Substring(128));
                IBufferedCipher cipher = CipherUtilities.GetCipher("AES/CBC/PKCS7Padding");
                cipher.Init(false, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", encryption_key), iv));

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CipherStream cipherStream = new CipherStream(memoryStream, null, cipher))
                    {
                        cipherStream.Write(input, 0, input.Length);
                    }

                    return Encoding.Unicode.GetString(memoryStream.ToArray());
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                show_two_line_message_in_console("Failed to Decrypt Ciphertext", "Error: " + ex.Message);
                Console.ForegroundColor = ConsoleColor.White;
                return "\"Decryption Failed\"";

            }
        }

        private static string Encrypt_hash_with_aes_in_cbc(byte[] input)
        {
            byte[] iv = GenerateRandomByteArray(16);
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/CBC/NoPadding");
            cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", encryption_key), iv));

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CipherStream cipherStream = new CipherStream(memoryStream, null, cipher))
                {
                    cipherStream.Write(input, 0, input.Length);
                }

                return BitConverter.ToString(EncryptAES(iv)).Replace("-", "") + BitConverter.ToString(memoryStream.ToArray()).Replace("-", "");
            }
        }

        private static byte[] Decrypt_hash_with_aes_in_cbc(string ciphertext)
        {
            byte[] encrypted_iv = StringToByteArray(ciphertext.Substring(0, 32));
            byte[] iv = DecryptAES(encrypted_iv);
            byte[] input = StringToByteArray(ciphertext.Substring(32));
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/CBC/NoPadding");
            cipher.Init(false, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", encryption_key), iv));

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CipherStream cipherStream = new CipherStream(memoryStream, null, cipher))
                {
                    cipherStream.Write(input, 0, input.Length);
                }

                return memoryStream.ToArray();
            }
        }

        private static byte[] EncryptAES(byte[] data)
        {
            // Create the AES cipher with ECB mode and no padding
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/ECB/NoPadding");
            cipher.Init(true, new KeyParameter(encryption_key));

            // Encrypt the data
            return cipher.DoFinal(data);
        }

        private static byte[] DecryptAES(byte[] encryptedData)
        {
            // Create the AES cipher with ECB mode and no padding
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/ECB/NoPadding");
            cipher.Init(false, new KeyParameter(encryption_key));

            // Decrypt the data
            return cipher.DoFinal(encryptedData);
        }

        public static int CalculateAsciiSum(string input)
        {
            int sum = 0;

            foreach (char character in input)
            {
                sum += (int)character;
            }

            return sum;
        }

        public static string HashStringWithSHA512(string input, int iterations)
        {
            using (SHA512 sha512 = SHA512.Create())
            {
                byte[] data = Encoding.UTF8.GetBytes(input);

                for (int i = 0; i < iterations; i++)
                {
                    data = sha512.ComputeHash(data);
                }

                // Convert the final hash to a hexadecimal string
                StringBuilder builder = new StringBuilder();
                foreach (byte b in data)
                {
                    builder.Append(b.ToString("x2"));
                }

                return builder.ToString();
            }
        }

        public static byte[] StringToByteArray(string hex)
        {
            int length = hex.Length;
            byte[] byteArray = new byte[length / 2];

            for (int i = 0; i < length; i += 2)
            {
                byteArray[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return byteArray;
        }

        private static byte[] CalculateHMACSHA256(byte[] data)
        {
            using (HMACSHA256 hmac = new HMACSHA256(verification_key))
            {
                return hmac.ComputeHash(data);
            }
        }
    }
}