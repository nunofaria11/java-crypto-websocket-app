package crypto;


import org.junit.Assert;
import org.junit.Test;

import javax.crypto.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

/**
 * Created by NunoFaria on 25-11-2016.
 */

public class CryptoUtilsTest {

    @Test
    public void generateSignKeyPair() {
        try {
            KeyPair keyPair = CryptoUtils.generateSignKeyPair();

            Assert.assertNotNull("Key pair not null", keyPair);
            System.out.println("Key-pair:\n" + keyPair.toString());

            Assert.assertNotNull("Private key not null", keyPair.getPrivate());
            System.out.println("Private key:\n" + keyPair.getPrivate().toString());

            Assert.assertNotNull("Public key not null", keyPair.getPublic());
            System.out.println("Public key:\n" + keyPair.getPublic().toString());

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void generateRandomSignKeyPair() {
        try {
            KeyPair keyPair = CryptoUtils.generateRandomSignKeyPair();

            Assert.assertNotNull("Key pair not null", keyPair);
            System.out.println("Key-pair:\n" + keyPair.toString());

            Assert.assertNotNull("Private key not null", keyPair.getPrivate());
            System.out.println("Private key:\n" + keyPair.getPrivate().toString());

            Assert.assertNotNull("Public key not null", keyPair.getPublic());
            System.out.println("Public key:\n" + keyPair.getPublic().toString());

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void generateWrapUnwrapKeyPair() {
        try {

            KeyPair keyPair = CryptoUtils.generateWrapUnwrapKeyPair();

            Assert.assertNotNull("Key pair not null", keyPair);
            System.out.println("Key-pair:\n" + keyPair.toString());

            Assert.assertNotNull("Private key not null", keyPair.getPrivate());
            System.out.println("Private key:\n" + keyPair.getPrivate().toString());

            Assert.assertNotNull("Public key not null", keyPair.getPublic());
            System.out.println("Public key:\n" + keyPair.getPublic().toString());

        } catch (NoSuchProviderException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void generateSignatureForPublicWrapKey() {

        try {
            KeyPair wrapKeyPair = CryptoUtils.generateWrapUnwrapKeyPair();
            KeyPair signKeyPair = CryptoUtils.generateSignKeyPair();

            byte[] publicEncoded = wrapKeyPair.getPublic().getEncoded();
            String publicEncodedB64 = Base64.getEncoder().encodeToString(publicEncoded);

            byte[] signature = CryptoUtils.generateSignature(signKeyPair.getPrivate(), publicEncodedB64.getBytes());
            Assert.assertNotNull("Signature not null", signature);
            System.out.println("Signature (bytes):\n" + Arrays.toString(signature));
            System.out.println("Signature (base64):\n" + Base64.getEncoder().encodeToString(signature));

        } catch (NoSuchProviderException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void generateAndVerifySignatureForPublicWrapKey() {
        try {
            // Get sign and verify keys
            KeyPair signKeyPair = CryptoUtils.generateSignKeyPair();

            // Prepare value to sign
            KeyPair wrapKeyPair = CryptoUtils.generateWrapUnwrapKeyPair();
            byte[] publicEncoded = wrapKeyPair.getPublic().getEncoded();
            String publicEncodedB64 = Base64.getEncoder().encodeToString(publicEncoded);

            // Sign value
            byte[] signature = CryptoUtils.generateSignature(signKeyPair.getPrivate(), publicEncodedB64.getBytes());

            String signatureStr = Base64.getEncoder().encodeToString(signature);
            Assert.assertNotNull("Signature not null", signature);
            System.out.println("Signature (bytes: " + signature.length + "):\n" + Arrays.toString(signature));
            System.out.println("Signature (base64):\n" + signatureStr);
            System.out.println("Data (bytes: " + publicEncoded.length + "):\n" + Arrays.toString(publicEncoded));
            System.out.println("Data (base64):\n" + publicEncodedB64);

            boolean verification = CryptoUtils.verifySignature(signKeyPair.getPublic(), signature, publicEncodedB64.getBytes());
            Assert.assertTrue("Verification passes", verification);

        } catch (NoSuchProviderException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void generateSignatureForValue() {

        try {
            KeyPair signKeyPair = CryptoUtils.generateSignKeyPair();

            String value = "test";
            String valueToSign = Base64.getEncoder().encodeToString(value.getBytes());

            byte[] signature = CryptoUtils.generateSignature(signKeyPair.getPrivate(), valueToSign.getBytes());
            Assert.assertNotNull("Signature not null", signature);
            System.out.println("Signature (bytes):\n" + Arrays.toString(signature));
            System.out.println("Signature (base64):\n" + Base64.getEncoder().encodeToString(signature));

        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            Assert.fail();
        }
    }


    @Test
    public void wrapKeyTest() {
        try {
            KeyPair wrapPair = CryptoUtils.generateWrapUnwrapKeyPair();

            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey secretKey = keyGenerator.generateKey();

            byte[] wrapped = CryptoUtils.wrapKey(wrapPair.getPublic(), secretKey);
            System.out.println("Wrapped bytes: " + Arrays.toString(wrapped));
            Assert.assertNotNull("Wrapped not null", wrapped);

        } catch (NoSuchProviderException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException e) {
            e.printStackTrace();
            Assert.fail("Error on wrap key test");
        }
    }

    @Test
    public void unwrapKeyTest() {
        try {
            KeyPair wrapPair = CryptoUtils.generateWrapUnwrapKeyPair();

            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey secretKey = keyGenerator.generateKey();

            byte[] wrapped = CryptoUtils.wrapKey(wrapPair.getPublic(), secretKey);
            System.out.println("Wrapped bytes: " + Arrays.toString(wrapped));
            Assert.assertNotNull("Wrapped not null", wrapped);

            SecretKey unwrappedKey = CryptoUtils.unwrapKey(wrapPair.getPrivate(), wrapped);

            System.out.println("Wrapped key: " + Arrays.toString(secretKey.getEncoded()));
            System.out.println("Unwrapped key: " + Arrays.toString(unwrappedKey.getEncoded()));
            Assert.assertArrayEquals("Wrapped and unprapped keys are equal", secretKey.getEncoded(), unwrappedKey.getEncoded());

        } catch (NoSuchProviderException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            Assert.fail("Error on wrap key test");
        }
    }

    @Test
    public void localWrapUnwrap_EncryptDecrypt_Test() {
        try {
            // Wrap/Unwrap
            KeyPair wrapPair = CryptoUtils.generateWrapUnwrapKeyPair();

            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey secretKeyA = keyGenerator.generateKey();

            byte[] wrapped = CryptoUtils.wrapKey(wrapPair.getPublic(), secretKeyA);
            System.out.println("Wrapped bytes: " + Arrays.toString(wrapped));
            Assert.assertNotNull("Wrapped not null", wrapped);

            SecretKey secretKeyB = CryptoUtils.unwrapKey(wrapPair.getPrivate(), wrapped);

            System.out.println("Secret key A: " + Arrays.toString(secretKeyA.getEncoded()));
            System.out.println("Secret key B: " + Arrays.toString(secretKeyB.getEncoded()));
            Assert.assertArrayEquals("Secret key A and B keys are equal", secretKeyA.getEncoded(), secretKeyB.getEncoded());

            // Encrypt/Decrypt
            String testMessage = "this is a test";
            EncryptedMessage encryptedMessageFromA = CryptoUtils.encrypt(secretKeyA, testMessage.getBytes());

            byte[] decryptedMessageInB = CryptoUtils.decrypt(secretKeyB, encryptedMessageFromA);
            String decryptedMessage = new String(decryptedMessageInB);

            System.out.println("Test message: \"" + testMessage + "\"");
            System.out.println("Decrypted message: \"" + decryptedMessage + "\"");

            Assert.assertEquals("Encrypted and decrypted messages are equal", testMessage, decryptedMessage);

            EncryptedMessage anotherEncryptedMessageFromA = CryptoUtils.encrypt(secretKeyA, testMessage.getBytes());
            Assert.assertFalse("Both encrypted messages must be different", Arrays.equals(anotherEncryptedMessageFromA.getData(), encryptedMessageFromA.getData()));

        } catch (NoSuchProviderException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            Assert.fail("Error on wrap/unwrap-encrypt/decrypt key test");
        }
    }
}
