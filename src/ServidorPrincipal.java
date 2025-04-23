import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.SecretKey;
import javax.crypto.spec.*;

public class ServidorPrincipal {
    private static final int PUERTO = 5000;
    private static Map<String, Servicio> servicios = new HashMap<>();
    private static PrivateKey llavePrivadaRSA;
    private static PublicKey llavePublicaRSA;
    private static final int MAX_CLIENTES = 32; 
    private static ExecutorService threadPool = Executors.newFixedThreadPool(MAX_CLIENTES);
    
    public static void main(String[] args) {
        // Inicializar tabla de servicios
        //inicializarServicios();
        
        // Paso 0a: Leer llaves de archivo 
        //cargarLlavesRSA();

        // Crear el socket del servidor, crea un hilo para cada cliente
        try(ServerSocket serverSocket = new ServerSocket(PUERTO)){
            System.out.println("Servidor listo y esperando en el puerto: "+PUERTO);
            while(true){
            Socket clientSocket = serverSocket.accept();
            System.out.println("1.  Cliente conectado: "+clientSocket.getInetAddress());
            ClienteHandler clientHandler = new ClienteHandler(clientSocket);
            clientHandler.start();
            }
            
        } catch(IOException e){
            System.out.println("No se pudo crear el socket en el puerto "+PUERTO);
        }
    
    }
    

    
    
    private static void inicializarServicios() {
        // Inicializar la tabla de servicios predefinida
        servicios.put("S1", new Servicio("Consulta de Vuelos", "S1", "192.168.1.10", 5001));
        servicios.put("S2", new Servicio("Disponibilidad de Vuelos", "S2", "192.168.1.11", 5002));
        servicios.put("S3", new Servicio("Costo de Vuelos", "S3", "192.168.1.12", 5003));
    }
    
    private static void cargarLlavesRSA() {
        try {
            // Cargar y decodificar llave privada RSA desde archivo .txt
            String privateKeyBase64 = new String(Files.readAllBytes(Paths.get("private.txt")));
            byte[] decodedPrivateKey = Base64.getDecoder().decode(privateKeyBase64);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(decodedPrivateKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            llavePrivadaRSA = keyFactory.generatePrivate(privateKeySpec);
            
            // Cargar y decodificar llave pública RSA desde archivo .txt
            String publicKeyBase64 = new String(Files.readAllBytes(Paths.get("public.txt")));
            byte[] decodedPublicKey = Base64.getDecoder().decode(publicKeyBase64);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decodedPublicKey);
            llavePublicaRSA = keyFactory.generatePublic(publicKeySpec);
            
            System.out.println("Llaves RSA cargadas correctamente.");
        } catch (Exception e) {
            System.err.println("Error cargando llaves RSA: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    
}