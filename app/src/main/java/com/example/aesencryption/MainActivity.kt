package com.example.aesencryption

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Base64
import android.util.Log
import com.google.gson.Gson
import java.lang.Exception
import java.math.BigInteger
import java.security.*
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and

import com.google.gson.annotations.SerializedName


data class User (

    @SerializedName("PayproID" ) var PayproID : String? = null,
    @SerializedName("PhoneN0"  ) var PhoneN0  : String? = null

)

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val user : User = User("10230030300","03331234567")
        val key = Base64.decode("RUMwbW1lcmNlRW5jcnlwdDFvbg==",0)
        encryptLogic(user,key);


    }
    //Encrypting Techniques
    fun encryptLogic(user: User, key:ByteArray) : String{
        val finalEncryption : String
        val gson = Gson()
        val encryptedKey = key.sha256()
        val IV = genrateIV()
        Log.d("Userjosn321",gson.toJson(user))
        //gson.toJson(user).toByteArray()
        val cipherText = encrypt("EC0mmerceEncrypt1on".toByteArray(), encryptedKey,IV)

        val cipherIVCombined = ByteArray(IV.size + (cipherText?.size ?: 0))
        if (cipherText != null && IV != null) {
            System.arraycopy(cipherText, 0, cipherIVCombined, 0, cipherText.size)
            System.arraycopy(IV, 0, cipherIVCombined, cipherText.size, IV.size)
            val cipherIVConvertedHmac = generateHashWithHmac256(cipherIVCombined,encryptedKey)

            val ivEncoded = Base64.encodeToString(IV,0)
            val cipherIVConvertedHmacEncoded = Base64.encodeToString(cipherIVConvertedHmac,0)
            val cipherTextEncoded = Base64.encodeToString(cipherText,0)

            finalEncryption = ivEncoded+":"+cipherIVConvertedHmacEncoded+":"+cipherTextEncoded
            Log.d("finalEncryption",finalEncryption)
            return finalEncryption
        }else {
            return ""
        }
    }

    // Public KeyGenerato
    fun getPublicKey(base64PublicKey: String): PublicKey? {
        var publicKey: PublicKey? = null
        try {
            val keySpec =
                X509EncodedKeySpec(Base64.decode(base64PublicKey.toByteArray(),1))
            val keyFactory = KeyFactory.getInstance("RSA")
            publicKey = keyFactory.generatePublic(keySpec)
            return publicKey
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
        } catch (e: InvalidKeySpecException) {
            e.printStackTrace()
        }
        Log.d("getPublicKey",""+publicKey)
        return publicKey
    }

    // Generating IV
    fun genrateIV(): ByteArray {

        val IV = ByteArray(16)
        var random: SecureRandom
        random = SecureRandom()
        random.nextBytes(IV)
        val string = String(IV, Charsets.UTF_8)
        Log.d("ase64.enco","test "+string.plus(" test"))

        return IV

    }

    // Generating hash key using SHA-256 algorithm

    fun ByteArray.sha256(): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        //return md.digest(toByteArray())
        return md.digest()
    }

    fun String.md5(): String {
        val md = MessageDigest.getInstance("MD5")
        return BigInteger(1, md.digest(toByteArray())).toString(16).padStart(32, '0')
    }

    // HMAC-SHA256 algorithm

    private fun generateHashWithHmac256(message: ByteArray, key: ByteArray) : ByteArray {

            val hashingAlgorithm = "HmacSHA256" //or "HmacSHA1", "HmacSHA512"
            val bytes = hmac(hashingAlgorithm, key, message)

            return bytes
    }

    fun hmac(algorithm: String?, key: ByteArray?, message: ByteArray?): ByteArray {
        val mac: Mac = Mac.getInstance(algorithm)
        mac.init(SecretKeySpec(key, algorithm))
        return mac.doFinal(message)
    }

    fun bytesToHex(bytes: ByteArray): String {
        val hexArray = "0123456789abcdef".toCharArray()
        val hexChars = CharArray(bytes.size * 2)
        var j = 0
        var v: Int
        while (j < bytes.size) {
            v = (bytes[j] and 0xFF.toByte()).toInt()
            hexChars[j * 2] = hexArray[v ushr 4]
            hexChars[j * 2 + 1] = hexArray[v and 0x0F]
            j++
        }
        return String(hexChars)
    }

    // AES Encryption
    @Throws(Exception::class)
    fun encrypt(
        plaintext: ByteArray?,
        key: ByteArray,
        IV: ByteArray?
    ): ByteArray? {
        val cipher: Cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        val keySpec = SecretKeySpec(key, "AES")
        val ivSpec = IvParameterSpec(IV)

      //  Log.d("``",Base64.encodeToString(cipher.iv,Base64.NO_WRAP))
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
        return cipher.doFinal(plaintext)
    }

    fun decrypt(cipherText: ByteArray?, key: ByteArray, IV: ByteArray?): String? {

            val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
            val keySpec = SecretKeySpec(key, "AES")
            val ivSpec = IvParameterSpec(IV)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
            val decryptedText = cipher.doFinal(cipherText)
            return String(decryptedText)

       // return null
    }
    fun RawCode(){
        //        var keyGenerator: KeyGenerator
//        var secretKey: SecretKey
//        keyGenerator = KeyGenerator.getInstance("AES")
//        keyGenerator.init(16)
//        secretKey = keyGenerator.generateKey()




//        try {
//            keyGenerator = KeyGenerator.getInstance("AES")
//            keyGenerator.init(16)
//            secretKey = keyGenerator.generateKey()
//
//            val str : String = "Iqrar"
//
//            val encrypt = encrypt(str.toByteArray(), secretKey, IV)
//            val encryptText = String(encrypt!!)
//            Log.d("encryptedText",encryptText )
//            Log.d("encryptedText2", IV.toString())
//            Log.d("encryptedText3", secretKey.toString())
//        } catch (e: Exception) {
//            e.printStackTrace()
//        }



        //  val messageDigest = bytesToHex(bytes)
        //  Log.i("HMAC-SHA256", "message digest: $messageDigest")


//val hash =generateHashWithHmac256(cipherText.toString().plus(encryptedKey),IV.toString())


        // val iv =  Base64.decode("tBTiE7swZbpBWIQYDXn2hg==",0)

        //   Log.d("String321",decrypt(ci,key,iv).toString())
    }
}
