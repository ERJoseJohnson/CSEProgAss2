import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.util.Scanner;

public class ClientSideCP1 {

	public static void main(String[] args) {

//    	String filename = "100.txt";
//    	if (args.length > 0) filename = args[0];
//
    	String serverAddress = "localhost";
//    	if (args.length > 1) filename = args[1];
//
    	int port = 4321;
//    	if (args.length > 2) port = Integer.parseInt(args[2]);

    	String filename;
    	Scanner userInput = new Scanner(System.in);
    	
		int numBytes = 0;

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;
        
        ClientAuthProtocol clientAuthentication;

//		long timeStarted = System.nanoTime();

		try {

			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

//			System.out.println("Creating Client Auth Obj...");
			
			clientAuthentication = new ClientAuthProtocol("cacse.crt");
			
	    	while(true) {
	    		long timeStarted = System.nanoTime();
	    			
	    			filename = userInput.nextLine();
	    			
	    			if(filename.equals("break")) {
//	    				System.out.println("Okay we closing now");
	    		        //Signal closing of server
	    		        toServer.writeInt(99);
	    		        
	    		        bufferedFileInputStream.close();
	    		        fileInputStream.close();

	    				System.out.println("Closing connection...");
	    				break;
	    			}
			
			
			// Generate Nonce
			System.out.println("Generating Nonce...");
			clientAuthentication.generateNonce(8);
			
			
			// Sending Nonce
			System.out.println("Sending nonce");
			toServer.writeInt(2);
			toServer.writeInt(clientAuthentication.getNonceLength());
//			System.out.println("Nonce that is being sent is "+new String(clientAuthentication.getNonce()));
			toServer.write(clientAuthentication.getNonce());
			
			
			// Receive nonce from server
			while(true) {
				int packetType = fromServer.readInt();
				if(packetType == 1) {
					System.out.println("Receiving encrypted nonce...");

					int lenOfEncryptedNonce = fromServer.readInt();
					byte [] encryptedNonce = new byte[lenOfEncryptedNonce];

//					System.out.println("The nonce received is "+new String(encryptedNonce));
					clientAuthentication.setEcnryptedNonce(encryptedNonce);
					break;
				}
				else {
					System.out.println("I did not receive the nonce :(");
//					break;
				}
				
			}

			
			// Request for Certificate
			System.out.println("Requesting CA signed cert...");
			toServer.writeInt(3);
			
			
			// Receive certificate
			while(true) {
				int packetType = fromServer.readInt();
				if(packetType == 2) {
					System.out.println("Receiving CA signed cert...");

					int lenOfCert = fromServer.readInt();
					byte [] ecnryptedCert = new byte[lenOfCert];
					fromServer.readFully(ecnryptedCert, 0, lenOfCert);
					
					
					// Decrypt Server cert and get server  Public key
					System.out.println("The certificate received is "+new String(ecnryptedCert));
					InputStream serverCertStream= new ByteArrayInputStream(ecnryptedCert);	
					clientAuthentication.getServerCertandPubKey(serverCertStream);
					break;
				}
				else {
					System.out.println("I did not receive the certificate :(");
//					break;
				}
				
			}
			
			
			// Verify certificate
			clientAuthentication.verifyServerCert();
			
			
			// Decrypt and compare nonce 
			boolean verified = clientAuthentication.compareNoncewithDecryptedMessage();
			if(verified) {
				System.out.println("Server is verified");
			}
			else {
				System.out.println("Server is not verified");
			}
			
			
			/* 
			 * Begin file sending
			*/
			
			// Start with filename
			toServer.writeInt(0);
			toServer.writeInt(filename.getBytes().length);
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

				// Print the normal file chunks
				System.out.println("Unencrypted file chunk: "+new String(fromFileBuffer));
				
				// Encrypting file chunks with server private key 
				// show the function inside ClientAuthProtocol class
				byte[] encryptedFileBuffer = clientAuthentication.encryptFileBits(fromFileBuffer);
				
				// Print encrypted bytes of file chunks
				System.out.println("Encrypted file chunk: "+ new String(encryptedFileBuffer));
				
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
			long timeTaken = System.nanoTime() - timeStarted;
			System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	    	}
		} catch (Exception e) {e.printStackTrace();}

	}
}
