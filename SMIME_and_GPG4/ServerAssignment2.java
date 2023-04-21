import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class ServerAssignment2 {
 
    private static DataOutputStream dataOutputStream = null;
    private static DataInputStream dataInputStream = null;

 
    public static void main(String[] args)
    {
        // Here we define Server Socket running on port 900
        try (ServerSocket serverSocket = new ServerSocket(999)) {
            System.out.println(
                "Server is Starting in Port 999");
            // Accept the Client request using accept method
            Socket clientSocket = serverSocket.accept();
            System.out.println("Connected");
            dataInputStream = new DataInputStream(clientSocket.getInputStream());
            dataOutputStream = new DataOutputStream(clientSocket.getOutputStream());
            receiveFile("PKCS12_cert.pem");
 
            dataInputStream.close();
            dataOutputStream.close();
            clientSocket.close();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
 
    // receive file function is start here
 
    private static void receiveFile(String fileName)
        throws Exception
    {
        String s;
        int bytes = 0;
        FileOutputStream fileOutputStream = new FileOutputStream(fileName);
 
        long size = dataInputStream.readLong();
        byte[] buffer = new byte[4 * 1024];
        while (size > 0 && (bytes = dataInputStream.read(buffer, 0, (int)Math.min(buffer.length, size))) != -1) {
            fileOutputStream.write(buffer, 0, bytes);
            size -= bytes;
            s = new String(buffer, StandardCharsets.UTF_8);
            System.out.println(s);
            
        }
        System.out.println("File is Received");
        fileOutputStream.close();
    }
}