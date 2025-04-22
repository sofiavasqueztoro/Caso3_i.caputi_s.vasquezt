import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.spec.*;
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
        inicializarServicios();
        
        // Paso 0a: Leer llaves de archivo (ya hecho en cargarLlavesRSA)
        cargarLlavesRSA();
        
        // Crear un thread pool para manejar múltiples conexiones de clientes
        threadPool = Executors.newFixedThreadPool(32); // Limitar el número de hilos

        try (ServerSocket serverSocket = new ServerSocket(PUERTO)) {
            System.out.println("Servidor principal iniciado en puerto " + PUERTO);
            
            while (true) {
                try {
                    Socket clienteSocket = serverSocket.accept();
                    System.out.println("Cliente conectado: " + clienteSocket.getInetAddress());
                    
                    // Crear y manejar cada cliente en un hilo delegado
                    threadPool.execute(new ManejadorCliente(clienteSocket));
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
            // Cargar llave privada RSA
            try (FileInputStream fis = new FileInputStream("private.key")) {
                byte[] encodedPrivate = fis.readAllBytes();
                PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivate);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                llavePrivadaRSA = keyFactory.generatePrivate(privateKeySpec);
            }
            
            // Cargar llave pública RSA
            try (FileInputStream fis = new FileInputStream("public.key")) {
                byte[] encodedPublic = fis.readAllBytes();
                X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublic);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                llavePublicaRSA = keyFactory.generatePublic(publicKeySpec);
            }
            
            System.out.println("Llaves RSA cargadas correctamente");
        } catch (Exception e) {
            System.err.println("Error cargando llaves RSA: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    static class ManejadorCliente implements Runnable {
        private Socket clienteSocket;
        private DataInputStream entrada;
        private DataOutputStream salida;
        private SecretKey llaveCifrado; // K_AB1
        private SecretKey llaveHMAC;    // K_AB2
        private byte[] iv;
        
        public ManejadorCliente(Socket socket) {
            this.clienteSocket = socket;
            try {
                this.entrada = new DataInputStream(socket.getInputStream());
                this.salida = new DataOutputStream(socket.getOutputStream());
            } catch (IOException e) {
                System.err.println("Error inicializando streams: " + e.getMessage());
            }
        }
        
        @Override
        public void run() {
            try {                
                
                // Paso 1: Recibir "HELLO" del cliente
                String mensaje = entrada.readUTF();
                if (!mensaje.equals("HELLO")) {
                    System.err.println("Mensaje incorrecto recibido. Se esperaba 'HELLO'");
                    return;
                }

                // Paso 2b: Recibir reto del cliente
                String reto = entrada.readUTF();
                System.out.println("Reto recibido: " + reto);

                // Paso 3: Calcular Rta = C(K_w-, Reto)
                byte[] retoBytes = reto.getBytes();
                byte[] rtaCalculada = CifradoUtils.cifrarRSAPrivada(retoBytes, llavePrivadaRSA);

                // Paso 4: Enviar Rta al cliente
                salida.writeInt(rtaCalculada.length);
                salida.write(rtaCalculada);
                salida.flush();

                // Paso 6: Recibir "OK" o "ERROR" del cliente
                String verificacion = entrada.readUTF();
                if (!verificacion.equals("OK")) {
                    System.err.println("Cliente reporta verificación fallida");
                    return;
                }
                
                // Paso 7: Generar G, P, G^a para Diffie-Hellman
                DHParameterSpec dhParams = CifradoUtils.generarParametrosDH();
                BigInteger p = dhParams.getP();
                BigInteger g = dhParams.getG();
                
                // Generar par de llaves DH para el servidor
                KeyPair servidorDHPair = CifradoUtils.generarParLlavesDH(dhParams);
                PublicKey servidorDHPublica = servidorDHPair.getPublic();
                
                // Paso 8: Enviar G, P, G^a y la firma F(K_w-, (G,P,G^a))
                // Enviar G
                byte[] gBytes = g.toByteArray();
                salida.writeInt(gBytes.length);
                salida.write(gBytes);
                
                // Enviar P
                byte[] pBytes = p.toByteArray();
                salida.writeInt(pBytes.length);
                salida.write(pBytes);
                
                // Enviar G^a (clave pública DH)
                byte[] gABytes = servidorDHPublica.getEncoded();
                salida.writeInt(gABytes.length);
                salida.write(gABytes);
                
                // Crear datos a firmar (G, P, G^a)
                ByteArrayOutputStream datosAFirmar = new ByteArrayOutputStream();
                datosAFirmar.write(gBytes);
                datosAFirmar.write(pBytes);
                datosAFirmar.write(gABytes);
                
                // Firmar con llave privada RSA
                byte[] firma = CifradoUtils.firmar(datosAFirmar.toByteArray(), llavePrivadaRSA);
                
                // Enviar firma F(K_w-, (G,P,G^a))
                salida.writeInt(firma.length);
                salida.write(firma);
                salida.flush();
                
                // Paso 10: Recibir respuesta del cliente
                String respuesta = entrada.readUTF();
                if (!respuesta.equals("OK")) {
                    System.err.println("Cliente rechazó los parámetros DH");
                    return;
                }
                
                // Paso 11a: Recibir G^y del cliente
                int gYLength = entrada.readInt();
                byte[] gYBytes = new byte[gYLength];
                entrada.readFully(gYBytes);
                
                // Reconstruir llave pública DH del cliente
                KeyFactory keyFactory = KeyFactory.getInstance("DH");
                X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(gYBytes);
                PublicKey clienteDHPublica = keyFactory.generatePublic(x509KeySpec);
                
                // Paso 11b: Calcular (G^y)^a = secreto compartido
                byte[] secretoCompartido = CifradoUtils.calcularLlaveSecretaDH(servidorDHPair.getPrivate(), clienteDHPublica);
                
                // Generar llaves simétricas para cifrado (K_AB1) y MAC (K_AB2)
                SecretKey[] llaves = CifradoUtils.generarLlavesSesion(secretoCompartido);
                llaveCifrado = llaves[0]; // K_AB1
                llaveHMAC = llaves[1];    // K_AB2
                
                // Paso 12a/12b: Recibir IV del cliente
                int ivLength = entrada.readInt();
                iv = new byte[ivLength];
                entrada.readFully(iv);
                
                // Paso 13: Enviar C(K_AB1, tabla_ids_servicios) y HMAC(K_AB2, tabla_ids_servicios)
                // Crear la tabla de servicios como string
                StringBuilder tablaIds = new StringBuilder();
                for (Servicio servicio : servicios.values()) {
                    tablaIds.append(servicio.toString()).append(";");
                }
                
                // Cifrar la tabla de servicios
                byte[] tablaCifrada = CifradoUtils.cifrarAES(tablaIds.toString().getBytes(), llaveCifrado, iv);
                
                // Generar HMAC
                byte[] hmac = CifradoUtils.generarHMAC(tablaCifrada, llaveHMAC);
                
                // Enviar tabla cifrada y HMAC
                salida.writeInt(tablaCifrada.length);
                salida.write(tablaCifrada);
                salida.writeInt(hmac.length);
                salida.write(hmac);
                salida.flush();
                
                // Paso 14: Recibir id_servicio+IP_cliente cifrado y su HMAC
                int mensajeCifradoLength = entrada.readInt();
                byte[] mensajeCifrado = new byte[mensajeCifradoLength];
                entrada.readFully(mensajeCifrado);
                
                int hmacLength = entrada.readInt();
                byte[] hmacRecibido = new byte[hmacLength];
                entrada.readFully(hmacRecibido);
                
                // Paso 15: Verificar HMAC y responder
                if (!CifradoUtils.verificarHMAC(mensajeCifrado, hmacRecibido, llaveHMAC)) {
                    salida.writeUTF("ERROR");
                    salida.flush();
                    System.err.println("Verificación HMAC fallida");
                    return;
                }
                
                // Descifrar el mensaje para obtener id_servicio
                byte[] mensajeClaro = CifradoUtils.descifrarAES(mensajeCifrado, llaveCifrado, iv);
                String mensajeStr = new String(mensajeClaro);
                
                // Extraer identificador de servicio (formato: id_servicio+IP_cliente)
                String[] partes = mensajeStr.split("\\+");
                String idServicio = partes[0];
                
                // Buscar servicio solicitado
                Servicio servicio = servicios.get(idServicio);
                String respuestaServicio;
                
                if (servicio != null) {
                    respuestaServicio = servicio.getIp() + "+" + servicio.getPuerto();
                } else {
                    respuestaServicio = "-1+-1";
                }
                
                // Paso 16: Enviar C(K_AB1, ip_servidor+puerto_servidor) y su HMAC
                byte[] respuestaCifrada = CifradoUtils.cifrarAES(respuestaServicio.getBytes(), llaveCifrado, iv);
                byte[] respuestaHMAC = CifradoUtils.generarHMAC(respuestaCifrada, llaveHMAC);
                
                salida.writeInt(respuestaCifrada.length);
                salida.write(respuestaCifrada);
                salida.writeInt(respuestaHMAC.length);
                salida.write(respuestaHMAC);
                salida.flush();
                
                // Paso 18: Recibir confirmación final
                String confirmacion = entrada.readUTF();
                System.out.println("Confirmación del cliente: " + confirmacion);
                
            } catch (Exception e) {
                System.err.println("Error en comunicación con cliente: " + e.getMessage());
                e.printStackTrace();
            } finally {
                try {
                    clienteSocket.close();
                } catch (IOException e) {
                    System.err.println("Error cerrando socket: " + e.getMessage());
                }
            }
        }
    }
}