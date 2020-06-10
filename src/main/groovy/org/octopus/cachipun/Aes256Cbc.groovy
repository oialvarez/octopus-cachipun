package org.octopus.cachipun

import lombok.SneakyThrows
import org.apache.commons.lang3.StringUtils

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

import static java.lang.Character.digit

class Aes256Cbc {
    static AES_CBC_PKCS_5_PADDING = "AES/CBC/PKCS5Padding"
    static ALGORITHM = "AES"
    static Cipher cipher
    static Base64.Encoder encoder
    static Base64.Decoder decoder
    final byte[] key
    final byte[] iv

    @SneakyThrows
    Aes256Cbc(String key, String iv) {
        this.key = hexStringToByteArray(key)
        this.iv = hexStringToByteArray(iv)
        cipher = Cipher.getInstance(AES_CBC_PKCS_5_PADDING)
        encoder = Base64.getEncoder()
        decoder = Base64.getDecoder()
    }

    private byte[] hexStringToByteArray(String s) {
        int len = s.length()
        byte[] data = new byte[len / 2]
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((digit(s.charAt(i), 16) << 4) + digit(s.charAt(i + 1), 16))
        }
        return data
    }

    String encryptBase64(String message) {
        byte[] encrypt = encrypt(message.getBytes())
        return encoder.encodeToString(encrypt)
    }

    private byte[] encrypt(byte[] message) {
        return encrypt(key, iv, message)
    }

    @SneakyThrows
    private byte[] encrypt(byte[] key, byte[] initializationVector, byte[] message) {
        SecretKey secretKey = new SecretKeySpec(key, 0, key.length, ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(initializationVector))
        return cipher.doFinal(message)
    }

    String decryptBase64(String toDecryptBase64) {
        String cleanedToDecryptBase64 = StringUtils.remove(toDecryptBase64, "\n")
        byte[] bytesBase64 = cleanedToDecryptBase64.getBytes()
        byte[] encrypted = decoder.decode(bytesBase64)
        byte[] decrypt = decrypt(encrypted)
        return new String(decrypt)
    }

    private byte[] decrypt(byte[] toDecrypt) {
        return decrypt(key, iv, toDecrypt)
    }

    @SneakyThrows
    private byte[] decrypt(byte[] key, byte[] initializationVector, byte[] encrypted) {
        SecretKey secretKey = new SecretKeySpec(key, 0, key.length, ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(initializationVector))
        return cipher.doFinal(encrypted)
    }
}
