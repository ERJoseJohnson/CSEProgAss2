import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.management.openmbean.InvalidKeyException;

public class ServerAuthProtocol {
	
//	private static PublicKey ServerPublicKey;
//	private static PublicKey CertificatePubKey;	
	private static PrivateKey ServerPrivateKey;
//	private static X509Certificate CAcert;
	private static X509Certificate ServerCert;
	private static byte[] nonce;
	private static byte[] encryptedNonce;
	private static byte[] ServerCertByteArrayform;
//	private static InputStream CAcertFile;
//	private static InputStream ServercertFile;
	private static Cipher EncryptCipher;
	private static Cipher decryptCipher;
	
	public ServerAuthProtocol(String privateKeyFilename, String ServerCertFilename) {
		try {
			ServerPrivateKey = getServerPrivateKey(privateKeyFilename);
			getServerCert(ServerCertFilename);
		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	private static void getServerCert(String filename) {
		try {
			FileInputStream CAcertFile = new FileInputStream(filename);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			ServerCert = (X509Certificate)cf.generateCertificate(CAcertFile);
			ServerCertByteArrayform = ServerCert.getEncoded();
		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	private static PrivateKey getServerPrivateKey(String filename) throws Exception {
				 
		byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
					 
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		kf.generatePrivate(spec);
		return kf.generatePrivate(spec);
	}
	
	public void encryptNonce(byte[] incomingNonce){
		try {
			nonce = incomingNonce;
			EncryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); 
			EncryptCipher.init(Cipher.ENCRYPT_MODE, ServerPrivateKey);
			encryptedNonce = EncryptCipher.doFinal(incomingNonce);
//			return encryptedNonce;
		}
		catch (java.security.InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
//		return nonce;
	}
	
	public static void setNonce(byte[] incomingNonce) {
		nonce = incomingNonce;
	}
	
	public int getEncryptedNonceLength() {
		return encryptedNonce.length;
	}
	
	public byte[] getEncryptedNonce() {
		return encryptedNonce;
	}
	
	public byte[] getSeverCertinByte() {
		return ServerCertByteArrayform;
	}
	
	public int getServerCertlength() {
		return ServerCertByteArrayform.length;
	}

}
