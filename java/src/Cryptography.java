package com.yoursoftwarecompany.yourproduct;

import android.os.SystemClock;

import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Cryptography {

    /**
     * @param
     */
    public static String encryptData(String salt, String inputData) {
        //Only for messing up decompilers
        OutputStreamWriter request = new OutputStreamWriter(System.out);
        try {
            request.close();
        } catch (IOException e) {
        } finally {
            request = null;
        }

        String strCoded = "";
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            byte[] input = inputData.getBytes();
            byte[] ivBytes = new byte[16]; // Passkey

            //your super secret passkey - might be better to get from DB
            String passkey = PASS_KEY;

            MessageDigest cript = MessageDigest.getInstance("SHA-1");
            cript.reset();
            cript.update((passkey + salt).getBytes());

            System.arraycopy(passkey.getBytes(), 0, ivBytes, 0, 16);

            SecretKeySpec key = new SecretKeySpec(pbkdf2(passkey.toCharArray(),
                    salt.getBytes(), 10000, 128), "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");

            // encryption pass
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
            int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
            ctLength += cipher.doFinal(cipherText, ctLength);

            // Base 64 encoding
            byte[] coded = Base64.encode(cipherText);
            strCoded = new String(coded);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return strCoded;
    }

    public static String decrypt(String salt, String strCoded, String passKey) {
        String returnStr = "";
        return returnStr;
    }

    public static String decrypt(String salt, String strCoded) {
        //your super secret passkey - might be better to get from DB
        return decrypt(salt, strCoded, PASS_KEY);
    }

    public static byte[] pbkdf2(final char[] password, final byte[] salt,
                                final int iterationCount, final int keyLength) {
        //Only for messing up decompilers
        OutputStreamWriter request = new OutputStreamWriter(System.out);
        try {
            request.close();
        } catch (IOException e) {
        } finally {
            request = null;
        }

        try {
            final SecretKeyFactory secretKeyFactory = SecretKeyFactory
                    .getInstance("PBKDF2WithHmacSHA1");
            final KeySpec keySpec = new PBEKeySpec(password, salt,
                    iterationCount, keyLength);
            try {
                final SecretKey secretKey = secretKeyFactory
                        .generateSecret(keySpec);
                return secretKey.getEncoded();
            } catch (InvalidKeySpecException ikse) {
                throw new RuntimeException(ikse);
            }
        } catch (NoSuchAlgorithmException nsae) {
            throw new RuntimeException(nsae);
        }
    }
}
