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
        
        // Crear un thread pool para manejar múltiples conexiones de clientes
        threadPool = Executors.newFixedThreadPool(32); // Limitar el número de hilos

        try (ServerSocket serverSocket = new ServerSocket(PUERTO)) {
            System.out.println("Servidor principal iniciado en puerto " + PUERTO);
            
            while (true) {
                try {
                    Socket clienteSocket = serverSocket.accept();
                    System.out.println("Cliente conectado: " + clienteSocket.getInetAddress());
                    
                    // Crear y manejar cada cliente en un hilo delegado
                    threadPool.execute(new ClienteHandler(clienteSocket));
                } catch (IOException e) {
                    System.err.println("Error aceptando conexión: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            System.err.println("Error al crear el socket del servidor: " + e.getMessage());
        } finally {
            // Cerrar el thread pool cuando el servidor termine
            if (threadPool != null) {
                threadPool.shutdown();
            }
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