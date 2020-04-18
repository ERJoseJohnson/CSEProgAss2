import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class ServerWithSecurity {
	public static void main(String[] args) {

    	int port = 4321;
    	if (args.length > 0) port = Integer.parseInt(args[0]);

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());
			
			ServerAuthProtocol serverAuthenticationProtocol = new ServerAuthProtocol("private_key.der","example-dc04d420-7ef6-11ea-ae9d-89114163ae84.crt");

			while (!connectionSocket.isClosed()) {

				int packetType = fromClient.readInt();

				// If the packet is for transferring the filename
				if (packetType == 0) {

					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					byte [] filename = new byte[numBytes];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(filename, 0, numBytes);

					fileOutputStream = new FileOutputStream("recv_"+new String(filename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {

					int numBytes = fromClient.readInt();
					byte [] block = new byte[numBytes];
					fromClient.readFully(block, 0, numBytes);

					if (numBytes > 0)
						bufferedFileOutputStream.write(block, 0, numBytes);

					if (numBytes < 117) {
						System.out.println("Closing connection...");

						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
						fromClient.close();
						toClient.close();
						connectionSocket.close();
					}
				// If the packet is for nonce exchange
				} else if (packetType == 2) {
					System.out.println("Receiving nonce...");

					int lenOfNonce = fromClient.readInt();
					byte [] nonce = new byte[lenOfNonce];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(nonce, 0, lenOfNonce);
					System.out.println("The nonce received is "+new String(nonce));
					
					System.out.println("Encrypting nonce...");
					// Store  and encrypt nonce to serverAuth Obj
					serverAuthenticationProtocol.encryptNonce(nonce);
					
					System.out.println("Sending encrypted nonce...");
					// Send Encrypted nonce
					toClient.writeInt(1);
					toClient.writeInt(serverAuthenticationProtocol.getEncryptedNonceLength());
					System.out.println("The encrypted nonce is "+new String(serverAuthenticationProtocol.getEncryptedNonce()));
					toClient.write(serverAuthenticationProtocol.getEncryptedNonce());
					
//					System.out.println("Closing connection...");
//					// Close all connections 
//					fromClient.close();
//					toClient.close();
//					connectionSocket.close();
					
				// If the packet is for certificate sending
				} else if (packetType == 3) {
					System.out.println("Certificate request received...");

					System.out.println("Sending CA signed certificate...");
					// Send Encrypted nonce
					toClient.writeInt(2);
					toClient.writeInt(serverAuthenticationProtocol.getServerCertlength());
					System.out.println("The encrypted server Cert is "+new String(serverAuthenticationProtocol.getSeverCertinByte()));
					toClient.write(serverAuthenticationProtocol.getSeverCertinByte());
					
					System.out.println("Closing connection...");
					// Close all connections 
					fromClient.close();
					toClient.close();
					connectionSocket.close();
				}

			}
		} catch (Exception e) {e.printStackTrace();}
	}
}

