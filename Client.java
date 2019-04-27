import java.io.*;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
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
		command = com;
	}
}

class ServerSendObject implements Serializable{
	byte[] block;	
	ServerSendObject(byte[] b){
		block = b;
	}
}


public class Client {
	

	public static byte[] AES(String message, byte[] key, byte[] ivBytes) throws Exception {

		IvParameterSpec iv = new IvParameterSpec(ivBytes);
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        byte[] encrypted = cipher.doFinal(message.getBytes());
        return encrypted;
	}
	
    public static byte[] RSA(PrivateKey privateKey, byte[] message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");  
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);  
        return cipher.doFinal(message);  
    }
    
	public static byte[] generateMAC(byte[] keybyte, byte[] message) throws Exception{ 

        SecretKey key = new SecretKeySpec(keybyte, 0, keybyte.length, "AES");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(key);
        byte[] digest = mac.doFinal(message);
        return digest;
	}

	public static void main(String args[]) throws Exception{

		String ServerIP = "127.0.0.1";
		int ServerPort = Integer.valueOf(args[0]);
		String fileName = args[1];
		
		String content = null;
	    File file = new File(fileName);
		FileReader reader = new FileReader(file);
		char[] chars = new char[(int) file.length()];
		reader.read(chars);
		content = new String(chars);
		reader.close();
				
		ArrayList<String> blocks = new ArrayList<>();
		for (int i=0; i<content.length(); i+=32) {
			blocks.add(content.substring(i,i+32));
		}
		
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(1024);
		KeyPair kp = kpg.generateKeyPair();
		PublicKey PUBK = kp.getPublic();
		PrivateKey privateKey = kp.getPrivate();
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(PUBK.getEncoded());
		byte[] sentPublic = x509EncodedKeySpec.getEncoded();

		SecureRandom random = new SecureRandom();
		byte[] AESK = new byte[16];
		random.nextBytes(AESK);
		
		SecureRandom randomiv = new SecureRandom();
		byte[] ivBytes = new byte[16];
		randomiv.nextBytes(ivBytes);
		ArrayList<byte[]> blocksG = new ArrayList<>();
		for (String Fi:blocks) {
			byte[] Gi = AES(Fi, AESK, ivBytes);
			blocksG.add(Gi);
		}
		
		ArrayList<byte[]> blocksH = new ArrayList<>();
		for (byte[] Gi:blocksG) {
			byte[] Hi = RSA(privateKey, Gi);
			blocksH.add(Hi);
		}
		
		ArrayList<byte[]> blocksHMac = new ArrayList<>();
		for (byte[] Hi:blocksH) {
			byte[] HiMac = generateMAC(AESK, Hi);
			blocksHMac.add(HiMac);
		}		

		Socket clientSocket1 = new Socket(ServerIP, ServerPort);
		
		ArrayList<byte[]> blocksF = new ArrayList<>();
		for (String Fi:blocks) {
			blocksF.add(Fi.getBytes());
		}
		
		ClientSendObject message = new ClientSendObject(sentPublic, AESK, blocksF, blocksH, ivBytes, "");
		ObjectOutputStream outToServer = new ObjectOutputStream(clientSocket1.getOutputStream());
		outToServer.writeObject(message);
		clientSocket1.close();
		
		while(true) {
			Scanner input = new Scanner(System.in);
		    String command = input.nextLine();
			Socket clientSocket2 = new Socket(ServerIP, ServerPort);			
			String [] commandParse = command.split(" ");
			
			if (commandParse[0].toLowerCase().equals("check")) {

				ClientSendObject messageCheck = new ClientSendObject(sentPublic, AESK, blocksF, blocksH, ivBytes, command);
				ObjectOutputStream outToServerCheck = new ObjectOutputStream(clientSocket2.getOutputStream());
				outToServerCheck.writeObject(messageCheck);	
				ObjectInputStream inStream = new ObjectInputStream(clientSocket2.getInputStream());
				ServerSendObject received = (ServerSendObject) inStream.readObject();
				byte[] receivedBlock = received.block;
				byte[] Received_HiMAC = generateMAC(AESK, receivedBlock);
				byte[] stored_HiMAC = blocksHMac.get(Integer.valueOf(commandParse[1]));
				if (Arrays.equals(Received_HiMAC, stored_HiMAC) ) {
					System.out.println( "Success!" );
				}
				else {
					System.out.println( "Fail!" );
				}
			}
			else if (commandParse[0].toLowerCase().equals("retrieve")) {
				ClientSendObject messageRetrieve = new ClientSendObject(sentPublic, AESK, blocksF, blocksH, ivBytes, command);
				ObjectOutputStream outToServerRetrieve = new ObjectOutputStream(clientSocket2.getOutputStream());
				outToServerRetrieve.writeObject(messageRetrieve);
				DataInputStream dataInput = new DataInputStream(clientSocket2.getInputStream());				
				byte[] receivedBlock = new byte[1000];
				int count = dataInput.read(receivedBlock);
				System.out.println(new String(receivedBlock) );
			}
		}
	}
}
