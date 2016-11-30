package crypto;


import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Created by NunoFaria on 25-11-2016.
 */
public class CryptoUtils {
    private final static String PUBLIC_KEY_PEM =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Ins0oje6R6iGJaHdJY2" +
                    "S8MrX0OkEBl3byePluYXChNwQ7RdRYfCJwd7zF6/ChhGsBTBWGzaZQ3JyGorZhPm" +
                    "W5YvrV1AOAACne6G6OxMRxvja4NSHzS8tsoR5zz7CCgWHfDxvy2TCwmeXgCrvMFo" +
                    "C/2ZWhyUhUo7SKk55MydSuZ1NsflASz7F2ywSKoD0iMB4dBLTIWkn3ZH99lMPWAh" +
                    "D686lY9DTHpTswG+4q5DXt9RBgCSw7+QHDxZcrpo7HaYQ0MYzwdWIUXQ9WYhz6SG" +
                    "lwHtpUB4sUBU5/kXxJGDabr9eXlKJMsY1ULnTpUzU5zYaf9VzUt+tKaXWhM/fDsn" +
                    "GwIDAQAB";


    // PKCS8 format
    private final static String PRIVATE_KEY_PEM =
            "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDQiezSiN7pHqIY" +
                    "lod0ljZLwytfQ6QQGXdvJ4+W5hcKE3BDtF1Fh8InB3vMXr8KGEawFMFYbNplDcnI" +
                    "aitmE+Zbli+tXUA4AAKd7obo7ExHG+Nrg1IfNLy2yhHnPPsIKBYd8PG/LZMLCZ5e" +
                    "AKu8wWgL/ZlaHJSFSjtIqTnkzJ1K5nU2x+UBLPsXbLBIqgPSIwHh0EtMhaSfdkf3" +
                    "2Uw9YCEPrzqVj0NMelOzAb7irkNe31EGAJLDv5AcPFlyumjsdphDQxjPB1YhRdD1" +
                    "ZiHPpIaXAe2lQHixQFTn+RfEkYNpuv15eUokyxjVQudOlTNTnNhp/1XNS360ppda" +
                    "Ez98OycbAgMBAAECggEBAJPLXHMtm8Xd9wW0EVYYa2ywapm+h5T9Z374q7RHZ8a1" +
                    "Vhg1yPDRMVGV5TBHad+OqvJ6EzlHFFUQO5T1YcKbkeQRAcM9VpkZsMEbXrPPXJP8" +
                    "+OWmkVoadzCY761Rs5vpRRt9OufCNfdZnsqCcTR6YfI1jiymGsCIhpGNlcFJHqUI" +
                    "fWaZeQCvofoFbrIDmEDncVjIlsrbWnrW5PzfnHrbo8eMG1Z8Q7UNT4cq8/kncBoB" +
                    "vht8ARsMbfDWDtATXPqTw1UctdZdetwnVqlLYPH7NA36PnKO/ZWqpQtlIelcpnqR" +
                    "YdD/EF+DYnkL1BaFVY3XZNSNYwPPmn5KnB7Sc2rnsLECgYEA+GRRlFcyVnpSk1I3" +
                    "MRTJN1sEs/H0C+Av8WxINBx+aab/zm/KbaJHxDYsNfv4nLf1HX5i6MReGcd8Mn40" +
                    "9TzrkL9Dn3TRpEtNVpTrVXJnMQMVoXeooi4eqNjvUiHasxK4i/kDKLPT3gUTg/ni" +
                    "1cOEB/1ItiJczgRJ8sWDZL8JdiMCgYEA1u0cmqEq/j8FcMJtiqOOz9gTeJoOhaXw" +
                    "7MLeEXCyA9ldwFciLGql4hw6h5VVS3WMO34rFDT6iDWcF2Dj+2e2CCUGvRns7xxn" +
                    "K3Dga8Jnvw2t77L2OWu7uBLtrWomf1hIk7z2rVAeGoHL8L8+7GKxMmDOlz1CC/14" +
                    "K936xhckzqkCgYEAkDmHmM9sfgP2kG3reAcusoKZ33X8kyywCckqv39P8z6xR4dn" +
                    "jXLtosMlto7AkxbJLz/kZG0oimVm+taHH2IpEVnNBPhKhc/nbv93CZ0sx6uX0rJs" +
                    "6wZGbRnRE+puVw3ms/d5WxfXTBG8fCQLDr3Amvb5Ui/vnPumiF0g5s15y+sCgYEA" +
                    "goutZyLj2WBwLoh6Ps6PzSEi2otArN8ZUsYeWpuIFRxvfIewYyg4L/oTdw02rMnu" +
                    "bqh5BCIV1qwxbmXUtHzPLW1IBY58wtQOum0qc2m22G43qzOZqVENyYX9xeqHDayT" +
                    "EOGjN6xFTLZwKIAReUWM+duhQG3d8yh3WLXRP4cJPVkCgYBFpR9a4IUpo2ArtV+W" +
                    "TlQmzysv8shL6mQ064oS9eWvX7GiTJrEd3Tc4J1/MCdDsf2vsCeuuKwhYZsxIbGx" +
                    "2L9H1YZ+df1LcbcHTR5292EO7k8CZAfwh1dDO1p4anP2qfpoHKEZWmWJBbE7sPX3" +
                    "fQr8t1drYFYJwm0e6MqtsJGUYQ==";

    private static final int SIGN_VERIFY_KEY_SIZE = 2048;
    private static final int WRAP_UNWRAP_KEY_SIZE = 2048;

    private static final String WRAP_UNWRAP_CIPHER_ALGORITHM = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    private static final String ENCRYPT_DECRYPT_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";

    public static KeyPair generateSignKeyPair() throws NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] privBytes = Base64.getDecoder().decode(PRIVATE_KEY_PEM);
        byte[] pubBytes = Base64.getDecoder().decode(PUBLIC_KEY_PEM);

        // private key
        KeySpec keySpec = new PKCS8EncodedKeySpec(privBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        // public key
        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(pubBytes);
        PublicKey publicKey = keyFactory.generatePublic(X509publicKey);

        return new KeyPair(publicKey, privateKey);
    }

    public static KeyPair generateRandomSignKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(SIGN_VERIFY_KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] generateSignature(PrivateKey signPrivateKey, byte[] data) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature dsa = Signature.getInstance("SHA256withRSA");
        dsa.initSign(signPrivateKey);
        dsa.update(data);
        return dsa.sign();
    }

    public static boolean verifySignature(PublicKey pubKey, byte[] signature, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature dsa = Signature.getInstance("SHA256withRSA");
        dsa.initVerify(pubKey);
        dsa.update(data);
        return dsa.verify(signature);
    }

    public static KeyPair generateWrapUnwrapKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException {
        // name: RSA-OAEP
        // modulusLength: 2048
        // publicExponent: 0x01, 0x00, 0x01
        // hash: SHA-1
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(WRAP_UNWRAP_KEY_SIZE, random);
        return generator.generateKeyPair();
    }


    public static SecretKey unwrapKey(PrivateKey priv, byte[] wrapped) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(WRAP_UNWRAP_CIPHER_ALGORITHM);
        cipher.init(Cipher.UNWRAP_MODE, priv);
        return (SecretKey) cipher.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
    }

    public static byte[] wrapKey(PublicKey publicKey, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(WRAP_UNWRAP_CIPHER_ALGORITHM);
        cipher.init(Cipher.WRAP_MODE, publicKey);
        return cipher.wrap(key);
    }


    public static EncryptedMessage encrypt(SecretKey key, byte[] message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(ENCRYPT_DECRYPT_CIPHER_ALGORITHM);

        // Generate random initialization vector
        byte[] ivBytes = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(ivBytes);

        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        SecretKeySpec skeySpec = new SecretKeySpec(key.getEncoded(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        byte[] encryptedMessage = cipher.doFinal(message);

        return new EncryptedMessage(encryptedMessage, ivBytes);
    }

    public static byte[] decrypt(SecretKey key, EncryptedMessage encryptedMessage) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(ENCRYPT_DECRYPT_CIPHER_ALGORITHM);
        IvParameterSpec iv = new IvParameterSpec(encryptedMessage.getIv());
        SecretKeySpec skeySpec = new SecretKeySpec(key.getEncoded(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        return cipher.doFinal(encryptedMessage.getData());
    }

}
