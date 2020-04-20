import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class ClientSideCP2 {
	
	private static SecretKey sessionKey;
	
	public static void main(String[] args) {

    	String filename = "CodeSnippet.png";
    	if (args.length > 0) filename = args[0];

    	String serverAddress = "localhost";
    	if (args.length > 1) filename = args[1];

    	int port = 4321;
    	if (args.length > 2) port = Integer.parseInt(args[2]);

		int numBytes = 0;

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

		long timeStarted = System.nanoTime();

		try {

			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			System.out.println("Creating Client Auth Obj...");
			
			ClientAuthProtocol clientAuthentication = new ClientAuthProtocol("cacse.crt");
			
			System.out.println("Generating Nonce...");
			// Generate Nonce
			clientAuthentication.generateNonce(8);
			
			System.out.println("Sending nonce");
			// Sending Nonce
			toServer.writeInt(2);
			toServer.writeInt(clientAuthentication.getNonceLength());
			System.out.println("Nonce that is being sent is "+new String(clientAuthentication.getNonce()));
			toServer.write(clientAuthentication.getNonce());
			
			// Receive nonce from server
			while(true) {
				int packetType = fromServer.readInt();
				if(packetType == 1) {
					System.out.println("Receiving encrypted nonce...");

					int lenOfEncryptedNonce = fromServer.readInt();
					byte [] encryptedNonce = new byte[lenOfEncryptedNonce];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromServer.readFully(encryptedNonce, 0, lenOfEncryptedNonce);
//					System.out.println("The nonce received is "+new String(encryptedNonce));
					clientAuthentication.setEcnryptedNonce(encryptedNonce);
					break;
				}
				else {
					System.out.println("I did not receive the nonce :(");
					break;
				}
				
			}
			
			System.out.println("Requesting CA signed cert...");
			// Request for Certificate
			toServer.writeInt(3);
			
			// Receive certificate
			while(true) {
				int packetType = fromServer.readInt();
				if(packetType == 2) {
					System.out.println("Receiving CA signed cert...");

					int lenOfCert = fromServer.readInt();
					byte [] ecnryptedCert = new byte[lenOfCert];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromServer.readFully(ecnryptedCert, 0, lenOfCert);
//					System.out.println("The certificate received is "+new String(ecnryptedCert));
					InputStream serverCertStream= new ByteArrayInputStream(ecnryptedCert);
					clientAuthentication.getServerCertandPubKey(serverCertStream);
					break;
				}
				else {
					System.out.println("I did not receive the certificate :(");
					break;
				}
				
			}
			
			// Validate cert
			clientAuthentication.verifyServerCert();
			
			// Decrypt and compare Nonce 
			boolean verified = clientAuthentication.compareNoncewithDecryptedMessage();
			if(verified) {
				System.out.println("Server is verified");
			}
			else {
				System.out.println("Server is not verified");
			}
			
			// Make session key
	        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
	        keyGen.init(128);
	        sessionKey = keyGen.generateKey();
	        byte[] sessionKeyinBytes = sessionKey.getEncoded();
//	        System.out.println("The session key is: "+new String(sessionKeyinBytes));
	        
	        // Encrypt session key with server public key
			Cipher sessionCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); 
			sessionCipher.init(Cipher.ENCRYPT_MODE, clientAuthentication.getServerPublicKey());
			byte[] encryptedKey = sessionCipher.doFinal(sessionKeyinBytes);
//			System.out.println("The length of the encrypted session key is: "+encryptedKey.length);
			
			// Send session key to client
			toServer.writeInt(4);
			toServer.writeInt(encryptedKey.length);
			toServer.write(encryptedKey);
			
			// Begin file sending
			
			// Start with filename
			toServer.writeInt(0);
			toServer.writeInt(filename.getBytes().length);
			// Encrypt filename byte array
//			byte[] encryptedBytes = clientAuthentication.encryptFileBits(filename.getBytes());
//			toServer.write(encryptedBytes);
			toServer.write(filename.getBytes());
			//toServer.flush();

			// Open the file
			fileInputStream = new FileInputStream(filename);
			bufferedFileInputStream = new BufferedInputStream(fileInputStream);

	        byte [] fromFileBuffer = new byte[117];

	        // Send the file
	        for (boolean fileEnded = false; !fileEnded;) {
				numBytes = bufferedFileInputStream.read(fromFileBuffer);
				fileEnded = numBytes < 117;

				System.out.println("Length of byte array from file stream buffer "+fromFileBuffer.length);
				
				byte[] encryptedFileBuffer = encryptFileBytes(fromFileBuffer);
				System.out.println("The length of the encrypted file bit is "+encryptedFileBuffer.length);
				toServer.writeInt(1);
				toServer.writeInt(numBytes);
				toServer.writeInt(encryptedFileBuffer.length);
				toServer.write(encryptedFileBuffer);
				toServer.flush();
			}
	        
	        // Signal end of file transmission
//	        toServer.writeInt(99);

	        bufferedFileInputStream.close();
	        fileInputStream.close();

			System.out.println("Closing connection...");

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}
	
	private static byte[] encryptFileBytes(byte[] fileBytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher sessionCipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); 
		sessionCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
		byte[] encryptedFileBytes = sessionCipher.doFinal(fileBytes);
		return encryptedFileBytes;
	}
}
