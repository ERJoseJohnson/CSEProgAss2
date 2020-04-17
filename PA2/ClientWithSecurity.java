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
