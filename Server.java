import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class ClientSendObject implements Serializable{
	byte[] PUBK;
	byte[] AESK;
	ArrayList<byte[]> blocksF;
	ArrayList<byte[]> blocksH;
	byte[] ivBytes;
	String command;
	
	ClientSendObject(byte[] p, byte[] A, ArrayList<byte[]> blocks, ArrayList<byte[]> blocksH2, byte[] iv, String com){
		PUBK = p;
		AESK = A;
		blocksF = blocks;
		blocksH = blocksH2;
		ivBytes = iv;
		command=com;
	}
}

class ServerSendObject implements Serializable{
	byte[] block;
	
	ServerSendObject(byte[] b){
		block = b;
	}
}

public class Server {
	
    public static byte[] RSA(PublicKey PUBK, byte [] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");  
        cipher.init(Cipher.DECRYPT_MODE, PUBK);
        
        return cipher.doFinal(encrypted);
    }
	
	public static byte[] AES(byte[] message, byte[] key, byte[] ivBytes) throws Exception {

		IvParameterSpec iv = new IvParameterSpec(ivBytes);
		SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
		byte[] encrypted = cipher.doFinal(message);
		return encrypted;
	}
	
	public static ArrayList<byte[]> decryptToF(ArrayList<byte[]> blocksH, PublicKey PUBK, byte[] AESK, 
			byte[] ivBytes) throws Exception {

		ArrayList<byte[]> ServerBlocksG = new ArrayList<>();
		for (byte[] Hi:blocksH) {
			byte[] Gi = RSA(PUBK, Hi);
			ServerBlocksG.add(Gi);
		}		
		ArrayList<byte[]> ServerBlocksF = new ArrayList<>();
		for (byte[] Gi: ServerBlocksG) {
			byte[] Fi = AES(Gi, AESK, ivBytes);
			ServerBlocksF.add(Fi);
		}
		return ServerBlocksF;
	}
	
	public static void main(String args[]) throws Exception{

		int ServerPort = Integer.valueOf(args[0]);		
		boolean Received = false;
		ServerSocket welcomeSocket = new ServerSocket(ServerPort);
		
		ArrayList<byte[]> ServerBlocksH = new ArrayList<>();
		byte[] AESK = new byte[16];
		byte[] IV = new byte[16];
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(1024);
		KeyPair kp = kpg.generateKeyPair();
		PublicKey PUBK = kp.getPublic();;
		while(true) {
			Socket connectionSocket = welcomeSocket.accept();
			ObjectInputStream inStream = new ObjectInputStream(connectionSocket.getInputStream());
			ClientSendObject received = (ClientSendObject) inStream.readObject();
			

			if (received.command.equals("")){
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(received.PUBK);
				PUBK = keyFactory.generatePublic(publicKeySpec);
				
				ArrayList<byte[]> ServerBlocksF = decryptToF(received.blocksH, PUBK, received.AESK, 
						received.ivBytes);
				
				for (int i=0; i<received.blocksF.size(); i++) {
					if (!Arrays.equals(received.blocksF.get(i), ServerBlocksF.get(i))) {
						System.out.println( "Cheating!!" );
						Received = false;
						break;
					}
					else Received = true;
				}
				if (Received) {
					System.out.println( "The client sends data successfully!!" );
					for (int i=0; i<received.blocksF.size(); i++) {
						ServerBlocksH.add(received.blocksH.get(i));
					}
					AESK = received.AESK;
					PUBK = keyFactory.generatePublic(publicKeySpec);
					IV = received.ivBytes;
				}
			}
			else{
				String [] command = received.command.split(" ");
				int indexBlock = Integer.parseInt(command[1]);
				if (command[0].toLowerCase().equals("check")){
					ServerSendObject message = new ServerSendObject(ServerBlocksH.get(indexBlock));
					ObjectOutputStream outToClient = new ObjectOutputStream(connectionSocket.getOutputStream());
					outToClient.writeObject(message);
				}
				else if(command[0].toLowerCase().equals("retrieve")){
					ArrayList<byte[]> ServerSendF = decryptToF(ServerBlocksH, PUBK, AESK, IV);
					DataOutputStream dataOut = new DataOutputStream(connectionSocket.getOutputStream());
					dataOut.write(ServerSendF.get(indexBlock));
				}
			} 
		}
	}
}
