import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AES {

	public static String encryption256(String strToEncrypt, String SECRET_KEY, String SALT) {
		try {
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			IvParameterSpec ivspec = new IvParameterSpec(iv);
			//IvParameterSpec ivspec = generateIv();

			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
			return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes()));
		} catch (Exception e) {
			System.out.println("Error while encrypting: " + e.toString());
		}
		return null;
	}

	public static String decrypt256(String strToDecrypt, String SECRET_KEY, String SALT) {
		try {
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			IvParameterSpec ivspec = new IvParameterSpec(iv);
			//IvParameterSpec ivspec = generateIv();

			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
			return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
		} catch (Exception e) {
			System.out.println("Error while decrypting: " + e.toString());
		}
		return null;
	}

	public static String decryptbaledung(String algorithm, String cipherText, SecretKey key)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
		return new String(plainText);
	}

	public static IvParameterSpec generateIv() {
		byte[] iv = new byte[16];
		new SecureRandom().nextBytes(iv);
		return new IvParameterSpec(iv);
	}

	public static SecretKey generateKey(int n, String key) throws NoSuchAlgorithmException {
//    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//    keyGenerator.init(n);
//    SecretKey key = keyGenerator.generateKey();
//    return key;
		byte[] keyparam = key.getBytes();
		SecretKeySpec keySpec = new SecretKeySpec(keyparam, "AES");
		return keySpec;
	}

	public static String encryptbaledung(String algorithm, String input, SecretKey key)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] cipherText = cipher.doFinal(input.getBytes());
		return Base64.getEncoder().encodeToString(cipherText);
	}

	public static void main(String[] args) throws UnsupportedEncodingException, GeneralSecurityException {
		String originalString = "CB8902C44E9222264~28-Jul-2021 16:02:44";
		
		String secretKey = "6FEA14735E4498A90175052342443AF11DAF83B0D93862C1692DF0E3226092F8";
		String salt = "DB65FC256FE33913";
		String iv = "8C1AB32E9317FA62AC240F962EFA341A";
		
		System.out.println(originalString);
		String encryptedString = encryption256(originalString, secretKey, salt);
		System.out.println(encryptedString);
		String decryptedString = decrypt256(encryptedString, secretKey, salt);
		System.out.println(decryptedString);

		// String input = "103070168";
		/*SecretKey key = generateKey(256, "wmsiecoenckeywmsiecoenckeywmsiec");
		IvParameterSpec ivParameterSpec = generateIv();
		// String algorithm = "AES/CBC/PKCS5Padding";
		String algorithm = "AES/ECB/PKCS5Padding";
		String encryptedString = encryptbaledung(algorithm, originalString, key);
		System.out.println(encryptedString);
		String decryptedString = decryptbaledung(algorithm, encryptedString, key);
		// Assertions.assertEquals(originalString, plainText);

		
		System.out.println(encryptedString);
		System.out.println(decryptedString);
		
		//employees.stream().filter(e -> e.getDept().equals("HR")).map(Employee::getSalary()).sum();
		
		Integer i1 = new Integer(100);
		Integer i2 = new Integer(100);		
		System.out.println(i1 == i2);*/
	}
}
