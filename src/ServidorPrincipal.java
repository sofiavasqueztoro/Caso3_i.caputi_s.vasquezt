import java.io.*;
import java.net.*;

public class ServidorPrincipal {
    private static final int PUERTO = 5000;
    private static boolean fin = false;
    
    public static void main(String[] args) {
        // Crear el socket del servidor, crea un hilo para cada cliente
        try(ServerSocket serverSocket = new ServerSocket(PUERTO)){
            System.out.println("Servidor listo y esperando en el puerto: "+PUERTO);
            while(!fin){
                Socket clientSocket = serverSocket.accept();
                System.out.println("1.  Cliente conectado: "+clientSocket.getInetAddress());
                ClienteHandler clientHandler = new ClienteHandler(clientSocket);
                clientHandler.start();
            }
            
        } catch(IOException e){
            System.out.println("No se pudo crear el socket en el puerto "+PUERTO);
        }
    
    }
    
}