import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class ClientAuthProtocol {
	
	private static PublicKey CertificatePubKey;
	private static PublicKey ServerPubKey;
	private static X509Certificate CAcert;
	private static X509Certificate ServerCert;
	private static byte[] nonce;
	private static byte[] decryptedNonce;
	private static InputStream CAcertFile;
	private static InputStream ServercertFile;
//	private static Cipher EncryptCipher;
	private static Cipher decryptCipher;
	
	public ClientAuthProtocol(String fileName) throws FileNotFoundException{
		CAcertFile = new FileInputStream(fileName);
		
		try {
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		CAcert =(X509Certificate)cf.generateCertificate(CAcertFile);
		CertificatePubKey = CAcert.getPublicKey();
		
		}
		catch(CertificateException ce) {
			ce.printStackTrace();
		}
	}
		
	
	// Compares to see if the retrieved Nonce from the server is the same as the one that the client sent
	public static boolean compareNoncewithDecryptedMessage(byte[] encryptedNonce) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException {
		try {
			decryptNonce(encryptedNonce);
			boolean serverVerified = Arrays.equals(nonce, decryptedNonce);
			return serverVerified;
		}
		catch(InvalidKeyException ike) {
			ike.printStackTrace();
		}
		catch(BadPaddingException bpe) {
			bpe.printStackTrace();
		}
		return false;
	}
	
	// Helper function for compareNOncewithDecryptedMessage
	// decprypts the ecnryptedNonce with the public key of the server
	private static void decryptNonce(byte[] encryptedNonce) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); 
		decryptCipher.init(Cipher.DECRYPT_MODE, ServerPubKey);
		
		decryptedNonce = decryptCipher.doFinal(encryptedNonce);
	}
	
	
	// Returns the nonce that is sent to the server for authentication
	public static byte[] getNonce(int n) {
		return nonce;
	}
	
	
	// Generates and saves the nonce that needs to be sent to the server
	public static byte[] generateNonce(int n) {
		
		String strNonce = getAlphaNumericString(n);
		
		nonce = strNonce.getBytes();
		
		return nonce;
	}

	// Helper function to generateNonce(int n)
	// Generates a random string that is n characters long
	private static String getAlphaNumericString(int n) { 
		
		// chose a Character random from this String 
		String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				+ "0123456789"
				+ "abcdefghijklmnopqrstuvxyz"; 
		
		// create StringBuffer size of AlphaNumericString 
		StringBuilder sb = new StringBuilder(n); 
		
		for (int i = 0; i < n; i++) { 
			
			// generate a random number between 
			// 0 to AlphaNumericString variable length 
			int index 
			= (int)(AlphaNumericString.length() 
					* Math.random()); 
			
			// add Character one by one in end of sb 
			sb.append(AlphaNumericString 
					.charAt(index)); 
		} 
		
		return sb.toString(); 
	} 
	
	// Helper function for getServerPublicKey(String filename)
	// Gets the public key of CA from the file that is sent from the server
	public static void getServerCert(InputStream serverStream) throws Exception{
//		CAcertFile = new FileInputStream(filename);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		ServerCert =(X509Certificate)cf.generateCertificate(serverStream);
	}
	
	
	public static void verifyServerCert() {
		try {
			ServerCert.verify(CertificatePubKey);
		}
		catch(SignatureException se) {
			se.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	// Gets the public key that is present from the certificate that is sent from the server
	public static PublicKey getServerPublicKey() throws Exception {
		 
//		getServerCert(serverStream);
		ServerPubKey = ServerCert.getPublicKey();
		return ServerPubKey;
	  }
	
	  
}
