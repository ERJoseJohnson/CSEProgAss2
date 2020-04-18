import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.net.Socket;

public class ClientWithSecurity {
	public static void main(String[] args) {

    	String filename = "100.txt";
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
					byte [] ecnryptedNonce = new byte[lenOfEncryptedNonce];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromServer.readFully(ecnryptedNonce, 0, lenOfEncryptedNonce);
					System.out.println("The nonce received is "+new String(ecnryptedNonce));
					break;
				}
				else {
					System.out.println("I did not receive anything :(");
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
					System.out.println("The nonce received is "+new String(ecnryptedCert));
					break;
				}
				else {
					System.out.println("I did not receive anything :(");
					break;
				}
				
			}
			
			// Decrypt Nonce 
			
			//Send Cert
			
			//Reveive file
			
//			// Send the filename
//			toServer.writeInt(0);
//			toServer.writeInt(filename.getBytes().length);
//			toServer.write(filename.getBytes());
//			//toServer.flush();
//
//			// Open the file
//			fileInputStream = new FileInputStream(filename);
//			bufferedFileInputStream = new BufferedInputStream(fileInputStream);
//
//	        byte [] fromFileBuffer = new byte[117];
//
//	        // Send the file
//	        for (boolean fileEnded = false; !fileEnded;) {
//				numBytes = bufferedFileInputStream.read(fromFileBuffer);
//				fileEnded = numBytes < 117;
//
//				toServer.writeInt(1);
//				toServer.writeInt(numBytes);
//				toServer.write(fromFileBuffer);
//				toServer.flush();
//			}

//	        bufferedFileInputStream.close();
//	        fileInputStream.close();

			System.out.println("Closing connection...");

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}
}
