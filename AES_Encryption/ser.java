import java.net.*;
import java.io.*;
import java.util.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import java.io.Console;


public class ser{
    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    public static void main(String[] args) throws Exception{
        try (ServerSocket ss = new ServerSocket(443)) {
            Socket s = ss.accept();
            System.out.println("Client connected");

            InputStreamReader in =  new InputStreamReader(s.getInputStream());
            Console console = System.console();
            
            // Generate ephemeral ECDH keypair
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(256);
            KeyPair kp = kpg.generateKeyPair();
            byte[] ourPk = kp.getPublic().getEncoded();

            // Display our public key
            console.printf("Public Key: %s%n", printHexBinary(ourPk));
      
            DataOutputStream dOut = new DataOutputStream(s.getOutputStream());
            dOut.writeInt(ourPk.length);
            dOut.write(ourPk);

            DataInputStream dIn = new DataInputStream(s.getInputStream());
            int length = dIn.readInt();
            byte[] otherPk = new byte[length];
            if(length>0){
                dIn.readFully(otherPk, 0 ,otherPk.length);
            }

            KeyFactory kf = KeyFactory.getInstance("EC");
            X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(otherPk);
            PublicKey otherPublicKey = kf.generatePublic(pkSpec);

            // Perform key agreement
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(kp.getPrivate());
            ka.doPhase(otherPublicKey, true);

            // Read shared secret
            byte[] sharedSecret = ka.generateSecret();
            console.printf("Shared secret: %s%n", printHexBinary(sharedSecret));

            // Derive a key from the shared secret and both public keys
            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            hash.update(sharedSecret);
            
            // Simple deterministic ordering
            List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(ourPk), ByteBuffer.wrap(otherPk));
            Collections.sort(keys);
            hash.update(keys.get(0));
            hash.update(keys.get(1));

            byte[] derivedKey = hash.digest();
            console.printf("Final key: %s%n", printHexBinary(derivedKey));

            String OUTPUT_FORMAT = "%-30s:%s";

            // encrypt and decrypt need the same key.
            // get AES 256 bits (32 bytes) key
            SecretKey secretKey = getAESKey(derivedKey); //Creates the same hex key as client

            // encrypt and decrypt need the same IV.
            // AES-GCM needs IV 96-bit (12 bytes)
            /* byte[] iv = getRandomNonce(IV_LENGTH_BYTE); */
            //Recieve IV 
            length = dIn.readInt();
            byte[] iv = new byte[length];
            if(length>0){
                dIn.readFully(iv, 0 ,iv.length);
            }
            dOut.writeInt(iv.length);
            dOut.write(iv);

            //Recieve Encrypted Text
            length = dIn.readInt();
            byte[] encryptedText = new byte[length];
            if(length>0){
                dIn.readFully(encryptedText, 0 ,encryptedText.length);
            }
            dOut.writeInt(encryptedText.length);
            dOut.write(encryptedText);


            System.out.println(String.format(OUTPUT_FORMAT, "Key (hex)", hex(secretKey.getEncoded())));
            System.out.println(String.format(OUTPUT_FORMAT, "IV  (hex)", hex(iv)));
            System.out.println(String.format(OUTPUT_FORMAT, "Encrypted (hex) ", hex(encryptedText)));
            System.out.println(String.format(OUTPUT_FORMAT, "Encrypted (hex) (block = 16)", hexWithBlockSize(encryptedText, 16)));

            System.out.println("\n------ AES GCM Decryption ------");
            System.out.println(String.format(OUTPUT_FORMAT, "Input (hex)", hex(encryptedText)));
            System.out.println(String.format(OUTPUT_FORMAT, "Input (hex) (block = 16)", hexWithBlockSize(encryptedText, 16)));
            System.out.println(String.format(OUTPUT_FORMAT, "Key (hex)", hex(secretKey.getEncoded())));
            
            String decryptedText = decryptWithPrefixIV(encryptedText, secretKey);

            System.out.println(String.format(OUTPUT_FORMAT, "Decrypted (plain text)", decryptedText));
        }
    }

    public static String hexWithBlockSize(byte[] bytes, int blockSize) {

        String hex = hex(bytes);

        // one hex = 2 chars
        blockSize = blockSize * 2;

        // better idea how to print this?
        List<String> result = new ArrayList<>();
        int index = 0;
        while (index < hex.length()) {
            result.add(hex.substring(index, Math.min(index + blockSize, hex.length())));
            index += blockSize;
        }

        return result.toString();

    }

    public static byte[] getRandomNonce(int numBytes) {
        byte[] nonce = new byte[numBytes];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    // hex representation
    public static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    public static byte[] parseHexBinary(String bitters)
    {
        byte[] b = bitters.getBytes();
        return b;
    }

    public static String printHexBinary(byte[] b)
    {
        String s = new String(b);
        return s;
    }

    public static byte[] encrypt(byte[] pText, SecretKey secret, byte[] iv) throws Exception {
    
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] encryptedText = cipher.doFinal(pText);
        return encryptedText;

    }

    public static String decrypt(byte[] cText, SecretKey secret, byte[] iv) throws Exception {

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] plainText = cipher.doFinal(cText);
        return new String(plainText, UTF_8);

    }

    public static String decryptWithPrefixIV(byte[] cText, SecretKey secret) throws Exception {

        ByteBuffer bb = ByteBuffer.wrap(cText);

        byte[] iv = new byte[IV_LENGTH_BYTE];
        bb.get(iv);
        //bb.get(iv, 0, iv.length);

        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);

        String plainText = decrypt(cipherText, secret, iv);
        return plainText;
    }

    public static SecretKey getAESKey(byte[] derivedKey) throws NoSuchAlgorithmException {
        SecretKey AESkey = new SecretKeySpec(derivedKey, "AES");
        return AESkey;
    }

    public static byte[] encryptWithPrefixIV(byte[] pText, SecretKey secret, byte[] iv) throws Exception {

        byte[] cipherText = encrypt(pText, secret, iv);

        byte[] cipherTextWithIv = ByteBuffer.allocate(iv.length + cipherText.length)
                .put(iv)
                .put(cipherText)
                .array();
        return cipherTextWithIv;

    }
    
}
