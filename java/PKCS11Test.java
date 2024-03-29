/*
 * Copyright (c) 2023 Markku Rossi.
 *
 * All rights reserved.
 */

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class PKCS11Test {
    private static Provider p;


    // RSA/ECB/PKCS1Padding (1024, 2048)
    // RSA/ECB/OAEPWithSHA-1AndMGF1Padding (1024, 2048)
    // RSA/ECB/OAEPWithSHA-256AndMGF1Padding (1024, 2048)


    public static void main(String[] args) {

        p = Security.getProvider("SunPKCS11");
        System.out.printf("Provider: %s\n", p);
        p = p.configure("pkcs11.cfg");
        Security.addProvider(p);

        System.out.printf("Provider: %s:\n%s\n", p.getName(), p.getInfo());

        testMessageDigest();
        testAES();
    }

    private static void testMessageDigest() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256", p);
            System.out.printf("MessageDigest: %s\n", md);

            md.update("Hello, world!".getBytes());
            byte[] digest = md.digest();

            System.out.printf("digest: %s\n", byteArrayToHex(digest));

        } catch (NoSuchAlgorithmException e) {
            System.err.printf("MessageDigest: %s\n", e);
        }
    }

    static String[] AESBlockCiphers = {
        "AES/CBC/NoPadding",
        "AES/CBC/PKCS5Padding",
        "AES/ECB/NoPadding",
        "AES/ECB/PKCS5Padding",
        "AES/CTR/NoPadding",
    };

/*
 * Modes such as Authenticated Encryption with Associated Data (AEAD)
 * provide authenticity assurances for both confidential data and
 * Additional Associated Data (AAD) that is not encrypted. (Please see
 * RFC 5116 for more information on AEAD and AEAD algorithms such as
 * GCM/CCM.) Both confidential and AAD data can be used when
 * calculating the authentication tag (similar to a Mac). This tag is
 * appended to the ciphertext during encryption, and is verified on
 * decryption.
 *
 * AEAD modes such as GCM/CCM perform all AAD authenticity calculations
 * before starting the ciphertext authenticity calculations. To avoid
 * implementations having to internally buffer ciphertext, all AAD data
 * must be supplied to GCM/CCM implementations (via the updateAAD
 * methods) before the ciphertext is processed (via the update and
 * doFinal methods).
 *
 * Note that GCM mode has a uniqueness requirement on IVs used in
 * encryption with a given key. When IVs are repeated for GCM
 * encryption, such usages are subject to forgery attacks. Thus, after
 * each encryption operation using GCM mode, callers should
 * re-initialize the cipher objects with GCM parameters which has a
 * different IV value.
 *
 *   GCMParameterSpec s = ...;
 *   cipher.init(..., s);
 *
 *   // If the GCM parameters were generated by the provider, it can
 *   // be retrieved by:
 *   // cipher.getParameters().getParameterSpec(GCMParameterSpec.class);
 *
 *   cipher.updateAAD(...);  // AAD
 *   cipher.update(...);     // Multi-part update
 *   cipher.doFinal(...);    // conclusion of operation
 *
 *   // Use a different IV value for every encryption
 *   byte[] newIv = ...;
 *   s = new GCMParameterSpec(s.getTLen(), newIv);
 *   cipher.init(..., s);
 *   ...
 */

    private static void testAES() {
        try {
            System.out.println("Creating AES secret key");

            char[] pin = "pin".toCharArray();
            KeyStore ks = KeyStore.getInstance("PKCS11", p);
            ks.load(null, pin);

            KeyGenerator gen = KeyGenerator.getInstance("AES", p);
            gen.init(128);
            Key key = gen.generateKey();

            System.out.printf("key: %s\n", key);

            String keyAlias = "AES key";
            char[] keyPIN = "pin".toCharArray();

            ks.setKeyEntry(keyAlias, key, keyPIN, null);
            ks.store(null);

            key = ks.getKey(keyAlias, keyPIN);

            System.out.println("Testing AES block ciphers");
            for (String alg : AESBlockCiphers) {
                System.out.printf("- %s\n", alg);
                try {
                    Cipher encrypt = Cipher.getInstance(alg, p);

                    encrypt.init(Cipher.ENCRYPT_MODE, key);

                    Cipher decrypt = Cipher.getInstance(alg, p);
                    byte[] iv = encrypt.getIV();

                    if (iv != null) {
                        decrypt.init(Cipher.DECRYPT_MODE, key,
                                     new IvParameterSpec(encrypt.getIV()));
                    } else {
                        decrypt.init(Cipher.DECRYPT_MODE, key);
                    }

                    testAESCipher(encrypt, decrypt);

                } catch (NoSuchAlgorithmException|NoSuchPaddingException
                         |InvalidKeyException|IllegalBlockSizeException
                         |InvalidAlgorithmParameterException
                         |BadPaddingException e) {
                    System.err.printf("Cipher '%s' failed: %s\n", alg, e);
                }
            }

            System.out.println("Testing AES GCM");
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", p);

                byte[] iv = new byte[12];
                for (int i = 0; i < iv.length; i++) {
                    iv[i] = (byte) i;
                }
                GCMParameterSpec spec = new GCMParameterSpec(128, iv);

                byte[] additional = new byte[20];
                for (int i = 0; i < additional.length; i++) {
                    additional[i] = (byte) i;
                }

                cipher.init(Cipher.ENCRYPT_MODE, key, spec);
                cipher.updateAAD(additional);

                testAESCipher(cipher, null);
            } catch (IllegalBlockSizeException|BadPaddingException
                     |InvalidAlgorithmParameterException
                     |NoSuchPaddingException|InvalidKeyException e) {
                System.err.printf("AES GCM: %s\n", e);
            }

        } catch (NoSuchAlgorithmException |KeyStoreException|IOException
                 |CertificateException|UnrecoverableKeyException e) {
            System.err.printf("Creating AES key failed: %s\n", e);
        }
    }

    private static void testAESCipher(Cipher encrypt, Cipher decrypt)
        throws IllegalBlockSizeException, BadPaddingException {

        System.out.printf("  - cipher   : %s\n", encrypt.getAlgorithm());
        System.out.printf("  - blockSize: %d\n", encrypt.getBlockSize());
        byte[] iv = encrypt.getIV();
        if (iv != null) {
            System.out.printf("  - IV       : %s\n", byteArrayToHex(iv));
        }
        byte[] plain = "Hello, world!!!!".getBytes();
        byte[] encrypted = encrypt.doFinal(plain);

        System.out.printf("  - plain    : %s\n", byteArrayToHex(plain));
        System.out.printf("  - encrypted: %s\n", byteArrayToHex(encrypted));

        if (decrypt == null) {
            return;
        }

        byte[] decrypted = decrypt.doFinal(encrypted);
        System.out.printf("  - decrypted: %s\n", byteArrayToHex(decrypted));

        if (!Arrays.equals(plain, decrypted)) {
            System.err.println("decrypted does not match plaintext");
            System.exit(1);
        }
    }

    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b: a) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
