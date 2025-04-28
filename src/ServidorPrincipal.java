import java.io.*;
import java.net.*;

public class ServidorPrincipal {
    private static final int PUERTO = 5000;
    private static boolean fin = false;
    public static Long tiempoFirmaTotal= 0L;
    public static long tiempoCifradoTablaTotal= 0L;
    public static long tiempoVerificacionTotal= 0L;
    public static long tiempo_tipoCifradoSimetricoTotal= 0L;
    public static long tiempo_tipoCifradoAsimetricoTotal= 0L;
    
    public static void main(String[] args) {
        //crear el socket del servidor
        try(ServerSocket serverSocket = new ServerSocket(PUERTO)){
            System.out.println("Servidor listo y esperando en el puerto: "+PUERTO);
            //creamos un thread de manejador de cliente, por el cual se ejecutara el protocolo del servidor para conectarse con el (o los) cliente(s)
            while(!fin){
                Socket clientSocket = serverSocket.accept();
                System.out.println("---Cliente conectado---");
                ClienteHandler clientHandler = new ClienteHandler(clientSocket);
                clientHandler.start();
            }  
        } catch(IOException e){
            System.out.println("No se pudo crear el socket en el puerto "+PUERTO);
        }
    
    }

    public static void stopServer() {
        //Cuando acaban las consultas, se imprimen los tiempos totales (suma de tiempos de las consultas)
        fin = true;
        System.out.println("El tiempo total para firmar fue: " + (double) tiempoFirmaTotal + " ms");
        System.out.println("El tiempo total para cifrar la tabla fue: " + (double) tiempoCifradoTablaTotal + " ms");
        System.out.println("El tiempo total para verificar de la consulta (HMAC) fue: " + (double) tiempoVerificacionTotal + " ms");
        System.out.println("El tiempo total para cifrar de forma simetrica fue: "+(double) tiempo_tipoCifradoSimetricoTotal+" ms");
        System.out.println("El tiempo total para cifrar de forma asimetrica fue: "+(double) tiempo_tipoCifradoAsimetricoTotal+" ms");
    }
    
}