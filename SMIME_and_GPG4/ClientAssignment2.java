import java.io.*;
import java.net.Socket;

public class ClientAssignment2 {
    private static DataOutputStream dataOutputStream = null;
    private static DataInputStream dataInputStream = null;

    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 999)) {
            dataInputStream = new DataInputStream(
                socket.getInputStream());
            dataOutputStream = new DataOutputStream(
                socket.getOutputStream());
            System.out.println(
                "Sending the File to the Server");
            
            sendFile("server-signed-cert.pem");

            dataInputStream.close();
            dataInputStream.close();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }


    private static void sendFile(String path) throws Exception {
        int bytes = 0;

        File file = new File(path);
        FileInputStream fileInputStream = new FileInputStream(file);

        dataOutputStream.writeLong(file.length());

        byte[] buffer = new byte[4 * 1024];
        while ((bytes = fileInputStream.read(buffer)) != -1) {
            dataOutputStream.write(buffer,0,bytes);
            dataOutputStream.flush();
        }
        fileInputStream.close();
        
    }
}