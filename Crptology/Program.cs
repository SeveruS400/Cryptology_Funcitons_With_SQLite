/*
 * @author=MahirFurkanKIR
 * 18253028
 * 
 */

using System;
using System.Data.SQLite;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;

namespace Crptology
{
   
    class Program
    {
        private const string AES_IV = @"!&+QWSDF!123126+"; //!Kriptolama için gerekli bilgiler
        static string aesKey = @"Qsaw!257()%ertas";
        static string aesKeyByte = @"0110101101001101";
        static bool pos = true; //pos ve pos2 değerleri while döngüleri için kullanılacaktır
        static bool pos2 = true;
        static bool notEmpty=false; //kullanıcı isminin daha önce alınıp alınmadığını kontrol etmek için
        static int ID;  //Giriş yapan kullanıcının ID bilgisi


        static void Main(string[] args)
        {
            SQLiteConnection sqliteConnection;  //Veritabanı ile bağlantı için
            sqliteConnection = CreateConnection();
            List<T> parts = new List<T>();  //Veritabanında gelecek verilerde farklı veri türleri olduğu için generic liste tercih edilmiştir
            Console.WriteLine("---------------------------------");
            Console.WriteLine("---------------------------------");
            Console.WriteLine("Hoşgeldiniz. Lütfen yapmak istediğiniz işlemi seçiniz...");
            Console.WriteLine("Oturum açmak için 1'e,");
            Console.WriteLine("Kayıt olmak için 2'ye basınız.");

            int choise = Convert.ToInt32(Console.ReadLine());

            while (pos == true) //Kullanıcıdan girilen numara ile yapılacak işleme yönlendiriliyor
            {
                if (choise == 1)    //Kayıtlı kullanılar için oturum açma kısmı
                {
                    Console.WriteLine("---------------------------------");
                    Console.Write("Kullanıcı Adı:");
                    string userName = Console.ReadLine();
                    Console.Write("Parola       :");
                    string password = Console.ReadLine();
                    Console.WriteLine("---------------------------------");
                    try
                    {

                        string num = getNumber();   //Rastgele sayı üretmek için
                        Console.WriteLine("Rastgele üretilen sayı: " + num);
                        Console.Write("Doğrulama kodunu giriniz: ");
                        string userNum = Console.ReadLine();

                        string hashedData = ComputeSha256Hash(num); // Sayının hashini almak için
                        string userHashedData = ComputeSha256Hash(userNum);

                        parts = ReadPublicKey(sqliteConnection);
                        string publicKeyLoad = parts[0].publicKey;   //Public Key'in veritabanından okunması


                        byte[] dataToEncrypt = Encoding.UTF8.GetBytes(hashedData); //Girilen sayının byte veri tipine dönüşümü
                        string ciphertext = Base64Encoding(rsaEncryption(publicKeyLoad, dataToEncrypt));  //RSA ile kriptolama işlemi
                                                                                                          //Console.WriteLine("Kriptolanmış veri: " + ciphertext);
                        InsertConfirmData(sqliteConnection, ciphertext);

                        string plaintext = ciphertext;

                        //InsertData(sqliteConnection, num, ciphertext, ID);

                        string privateKeyLoad = File.ReadAllText("privateKey.xml");//Secret Key'in dosyadan okunması
                        byte[] plaintext2 = Base64Decoding(plaintext);
                        byte[] decryptedtextByte = rsaDecryption(privateKeyLoad, plaintext2); //Decrypted işlemi
                        string decryptedtext2 = Encoding.UTF8.GetString(decryptedtextByte, 0, decryptedtextByte.Length);
                        //Console.WriteLine(userHashedData);
                        //Console.WriteLine(ciphertext);
                        //Console.WriteLine(decryptedtext2);

                        if (userHashedData == decryptedtext2)
                        {
                            parts = ReadData(sqliteConnection, userName, password);
                            if (parts.Count != 0)   // Veritabanında yapılan sorgu boş değil ise giriş başarılı ve pos==false ile ilk döngüden çıkış
                            {
                                
                                ID = parts[0].rID;
                                pos = false;
                                Console.WriteLine("Giriş başarılı");
                            }
                            else
                            {
                                Console.WriteLine("Kullanıcı adı/parola hatalı giriş");
                            }

                        }
                        else
                        {
                            Console.WriteLine("Hatalı giriş kodu");

                        }
                        //Console.WriteLine("Kriptosu çözülmüş veri: " + decryptedtext2);


                    }
                    catch (ArgumentNullException e)
                    {
                        Console.WriteLine(e);
                    }
                }

                else if (choise == 2)   //Yeni kullanıcı kaydı
                {
                    Console.WriteLine("---------------------------------");
                    Console.WriteLine("Kullanıcı Adı:");
                    string userName = Console.ReadLine();
                    Console.WriteLine("Parola       :");
                    string password = Console.ReadLine();
                    Console.WriteLine("---------------------------------");
                    CheckUser(sqliteConnection, userName);
                    if (notEmpty == false)  // Kullanıcı adı daha önce alınmamış ise kayıt işlemi yapılır
                    {
                        //string num = getNumber();
                        //RsaEncryption rsa = new RsaEncryption();
                        //string cypher = string.Empty;
                        //cypher = rsa.RSAEncrypted(num);

                        /*InsertUser(sqliteConnection, userName, password);*/
                        Console.WriteLine("Kayıt başarılı. Lütfen oturum açınız.");
                        choise = 1;
                    }
                    else //Kullanıcı adı alınmış ise başka bir kullanıcı adı girilmesi için işlem tekrarlanır
                    {
                        Console.WriteLine("Kullanıcı adı daha önce alınmış. Lütfen farklı bir kullanıcı adı deneyiniz.");
                        notEmpty = false;
                    }                    
                }

                else //Belirtilen sayıların haricinde tuşlama yapıldığı durum
                {
                    Console.WriteLine("Hatalı tuşlama yaptınız. Lütfen tekrar deneyiniz.");
                    choise = Convert.ToInt32(Console.ReadLine());
                }                                               
            }

            while (pos2 == true)    //Oturumu açan kulanıcıların veri kaydetme ve son veriyi listelemek için kullanacağı kısım
            {
                Console.WriteLine("---------------------------------");
                Console.WriteLine("Veri kaydetmek için 1'e basınız.");
                Console.WriteLine("Kaydedilen son veriye erişmek için 2'ye basınız.");
                Console.WriteLine("Çıkmak için başka bir sayıya basınız.");

                int number = Convert.ToInt32(Console.ReadLine());
                if (number == 1)    //Veritabanına yeni veri kaydı eklemek için
                {
                    Console.WriteLine("Kaydetmek istediğiniz veriyi giriniz:");
                    String plaintxt = Console.ReadLine();   //Girilen metin
                    Console.WriteLine("Kripolama anahtarını seçiniz.");
                    int num= Convert.ToInt32(Console.ReadLine());
                    String chipertxt = AEScrypted(plaintxt,num);    // Kriptolanmış metin
                    InsertData(sqliteConnection, plaintxt, chipertxt, ID);
                    Console.WriteLine("Veri kaydedilmiştir.");

                }
                else if (number == 2)   //Veritabanına kayıtlı son veriyi getirir(ID değişkeni ile sadece oturumu açan kişinin son verisi gelir) 
                {
                    parts = getLastData(sqliteConnection, ID);
                    string lastData = parts[0].rdata;
                    Console.Write("Girilen son metin: ");
                    Console.WriteLine(AESDecrypted(lastData));
                }

                else  //Uygulamadan çıkış
                {
                    Console.WriteLine("Exit");
                    pos2= false;
                }
            }
        }
        static string ComputeSha256Hash(string rawData)     // SHA256 ile verinin hashlenmesi
        {
            // Create a SHA256   
            using (SHA256 sha256Hash = SHA256.Create())
            {
                // ComputeHash - returns byte array  
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

                // Convert byte array to a string   
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }

        //static RSAParameters publicKey;
        //static string privateKey = "privateKey.xml";
        public static byte[] rsaEncryption(string publicKey, byte[] plaintext)  //RSA algoritması ile verinin kriptolanması
        {
            RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider(2048);
            RSAalg.PersistKeyInCsp = false;
            RSAalg.FromXmlString(publicKey);
            return RSAalg.Encrypt(plaintext, true);
        }

        public static byte[] rsaDecryption(string privateKey, byte[] ciphertext)    //RSA algoritması ile kriptolu verinin çözümlenmesi
        {
            RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider(2048);
            RSAalg.PersistKeyInCsp = false;
            RSAalg.FromXmlString(privateKey);
            return RSAalg.Decrypt(ciphertext, true);
        }

        static string Base64Encoding(byte[] input)
        {
            return Convert.ToBase64String(input);
        }

        static byte[] Base64Decoding(String input)
        {
            return Convert.FromBase64String(input);
        }
        static public string getNumber()    //Rastgele sayı üretme algoritması
        {
            Random rand = new Random();
            long randnum = (long)(rand.NextDouble() * 9000000000) + 1000000000;
            return randnum.ToString();
        }

        static string AEScrypted(string data,int num)   //AES ile girilen verilerin kriptolanma işleminin gerçekleştiği yer
        {
            AesCryptoServiceProvider aesPorvider = new AesCryptoServiceProvider();
            aesPorvider.BlockSize = 128;
            aesPorvider.KeySize = 128;
            aesPorvider.IV = Encoding.UTF8.GetBytes(AES_IV);
            if (num == 0)
            {
                aesPorvider.Key = Encoding.UTF8.GetBytes(aesKey);
            }
            else
            {
                aesPorvider.Key = Encoding.UTF8.GetBytes(aesKeyByte);
            }
            
            aesPorvider.Mode = CipherMode.CBC;
            aesPorvider.Padding = PaddingMode.PKCS7;

            byte[] source = Encoding.Unicode.GetBytes(data);
            using (ICryptoTransform sifrele = aesPorvider.CreateEncryptor())
            {
                byte[] target = sifrele.TransformFinalBlock(source, 0, source.Length);
                return Convert.ToBase64String(target);
            }
        }
        static string AESDecrypted(string data) //AES ile gelen verinin okunabilir hale getirme işleminin gerçekleştiği yer
        {
            AesCryptoServiceProvider aesPorvider = new AesCryptoServiceProvider();
            aesPorvider.BlockSize = 128;
            aesPorvider.KeySize = 128;

            aesPorvider.IV = Encoding.UTF8.GetBytes(AES_IV);
            aesPorvider.Key = Encoding.UTF8.GetBytes(aesKey);
            aesPorvider.Mode = CipherMode.CBC;
            aesPorvider.Padding = PaddingMode.PKCS7;

            byte[] source = System.Convert.FromBase64String(data);
            using (ICryptoTransform decrypt = aesPorvider.CreateDecryptor())
            {
                byte[] target = decrypt.TransformFinalBlock(source, 0, source.Length);
                return Encoding.Unicode.GetString(target);
            }
        }

        static SQLiteConnection CreateConnection()  //SQLite veritabanın bağlanmak için 
        {
            SQLiteConnection sqliteConn;
            sqliteConn = new SQLiteConnection("Data Source=database.db; Version = 3; New = True; Compress = True;");
            try
            {
                sqliteConn.Open();
            }
            catch
            {
                Console.WriteLine("Veritabanına bağlanılamadı");
            }
            return sqliteConn;
        }

        static void CreateTable(SQLiteConnection conn)  //Veritabanı içerisinde tablo oluşturmak için(Projenin başlangıcında bu fonksiyon kullanılmıştır fakat şuanda kullanılmamaktadır)
        {
            SQLiteCommand sqliteCommand;
            string createSQL = "CREATE TABLE user(ID INT, userName TEXT,password TEXT)";
            sqliteCommand = conn.CreateCommand();
            sqliteCommand.CommandText = createSQL;
            sqliteCommand.ExecuteNonQuery();
        }

        static void InsertUser(SQLiteConnection conn,string userName,string password)   //Kayıt olan kullanıcıların veritabanına kayıt edilmesi
        {
            SQLiteCommand sqliteCommand;
            sqliteCommand = conn.CreateCommand();
            sqliteCommand.CommandText = "INSERT INTO user(userName, password) VALUES (@userName, @password);";
            sqliteCommand.Parameters.Add(new SQLiteParameter("userName",userName));
            sqliteCommand.Parameters.Add(new SQLiteParameter("password",password));
            sqliteCommand.ExecuteNonQuery();
            
        }
        static void InsertData(SQLiteConnection conn, string chipertxt,string plaintxt, int ID)  //Oturum açan kullanıcının girdiği verilerin veritabanına kayıt edilmesi
        {
            SQLiteCommand sqliteCommand;
            sqliteCommand = conn.CreateCommand();
            sqliteCommand.CommandText = "INSERT INTO data(userID,chiperData, plainData) VALUES (@userID, @chiperData,@plainData);";
            sqliteCommand.Parameters.Add(new SQLiteParameter("userID", ID));
            sqliteCommand.Parameters.Add(new SQLiteParameter("chiperData", chipertxt));
            sqliteCommand.Parameters.Add(new SQLiteParameter("plainData", plaintxt));
            sqliteCommand.ExecuteNonQuery();

        }
        static void InsertConfirmData(SQLiteConnection conn, string hashedData)  //Oturum açan kullanıcının girdiği verilerin veritabanına kayıt edilmesi
        {
            SQLiteCommand sqliteCommand;
            sqliteCommand = conn.CreateCommand();
            sqliteCommand.CommandText = "INSERT INTO userConfirm(hashData) VALUES (@hashData);";
            sqliteCommand.Parameters.Add(new SQLiteParameter("hashData", hashedData));
            sqliteCommand.ExecuteNonQuery();

        }

        static void CheckUser(SQLiteConnection conn, string userName)   //Yeni kayıt olacak kişinin seçtiği kullanıcı adının daha önceden alınıp alınmadığını kontrol eder
        {
            List<T> parts = new List<T>();
            SQLiteDataReader sqliteReader;
            SQLiteCommand sqliteCommand;
            sqliteCommand = conn.CreateCommand();
            sqliteCommand.CommandText = "SELECT * FROM user WHERE userName==@userName";
            sqliteCommand.Parameters.Add(new SQLiteParameter("userName", userName));
            sqliteReader = sqliteCommand.ExecuteReader();
            while (sqliteReader.Read())
            {
                int rID = sqliteReader.GetInt32(0);
                string rName = sqliteReader.GetString(1);
                string rPass = sqliteReader.GetString(2);

                parts.Add(new T() { rID = rID, rName = rName, rPass = rPass });
            }
            if (parts.Count > 0)
            {
                notEmpty = true;
            }
        }

        static List<T> getLastData(SQLiteConnection conn, int ID)//Kullanıcının girmiş olduğu son veriyi getirir
        {
            List<T> parts = new List<T>();
            SQLiteDataReader sqliteReader;
            SQLiteCommand sqliteCommand;
            sqliteCommand = conn.CreateCommand();
            sqliteCommand.CommandText = "SELECT plainData FROM data WHERE userID==@ID ORDER BY ID DESC LIMIT 1 ";
            sqliteCommand.Parameters.Add(new SQLiteParameter("ID", ID));
            sqliteReader = sqliteCommand.ExecuteReader();
            while (sqliteReader.Read())
            {         
                string rdata = sqliteReader.GetString(0);
                parts.Add(new T() { rdata = rdata });
            }

            return parts;
        }

        static List<T> ReadData(SQLiteConnection conn, string userName, string password)//Kullanıcının oturum açma aşamasında verileri doğrulamak için kullanılır
        {
            List<T> parts = new List<T>();
            SQLiteDataReader sqliteReader;
            SQLiteCommand sqliteCommand;
            sqliteCommand = conn.CreateCommand();
            sqliteCommand.CommandText = "SELECT * FROM user WHERE userName==@userName AND password==@password";
            sqliteCommand.Parameters.Add(new SQLiteParameter("userName", userName));
            sqliteCommand.Parameters.Add(new SQLiteParameter("password", password));
            sqliteReader = sqliteCommand.ExecuteReader();
            while (sqliteReader.Read())
            {
                int rID = sqliteReader.GetInt32(0);
                string rName = sqliteReader.GetString(1);
                string rPass = sqliteReader.GetString(2);

                parts.Add(new T() { rID = rID, rName = rName, rPass = rPass });


            }

            return parts;
        }
        static List<T> ReadPublicKey(SQLiteConnection conn)//Public anahtarı database üzerinden okunması
        {
            List<T> parts = new List<T>();
            SQLiteDataReader sqliteReader;
            SQLiteCommand sqliteCommand;
            sqliteCommand = conn.CreateCommand();
            sqliteCommand.CommandText = "SELECT * FROM publicKey ";
            sqliteReader = sqliteCommand.ExecuteReader();
            while (sqliteReader.Read())
            {
                string publicKey = sqliteReader.GetString(0);
                parts.Add(new T() { publicKey = publicKey });
            }
            return parts;
        }

        /*Veritabanında gelen verilerde hem int hem de string değerler olduğu için generic bir list ihtiyacı olmuştur
         * Bu sebeple vertabanından gelen veriler için ayrı ayrı get ve set değerleri oluşturulmuştur
         * parts[n].rdata yazarak gelen n'inci verinin içerisindeki data kısmına erişebiliriz.
         */
        public class T  
        {
            public int rID { get;set;}
            public string rName { get;set;}
            public string rPass { get;set;}
            public string rdata { get;set;}
            public string publicKey { get; set; }
            public override string ToString()
            {
                return "ID: " + rID + "   Name: " + rName + "   Password:"+ rPass+ " chiperData:" + rdata + " Public Key:" + publicKey;
            }
        }
    }
}
