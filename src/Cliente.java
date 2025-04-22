import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.SecretKey;
import javax.crypto.spec.*;

public class Cliente {
    private static final String HOST_SERVIDOR = "localhost";
    private static final int PUERTO_SERVIDOR = 5000;
    private static PublicKey llavePublicaRSA;
    
    public static void main(String[] args) {
        // Paso 0b: Cargar llave pública RSA del servidor
        cargarLlavePublica();
        
        try (Socket socket = new Socket(HOST_SERVIDOR, PUERTO_SERVIDOR);
             DataInputStream entrada = new DataInputStream(socket.getInputStream());
             DataOutputStream salida = new DataOutputStream(socket.getOutputStream())) {
            
            System.out.println("Conectado al servidor principal: " + HOST_SERVIDOR + ":" + PUERTO_SERVIDOR);
            
            // Paso 1: Enviar "HELLO"
            salida.writeUTF("HELLO");
            salida.flush();

            // Paso 2a: Generar un reto aleatorio
            String reto = CifradoUtils.generarReto();
            System.out.println("Reto generado: " + reto);

            // Paso 2b: Enviar el reto al servidor
            salida.writeUTF(reto);
            salida.flush();

            // Paso 4: Recibir Rta del servidor
            int rtaLength = entrada.readInt();
            byte[] rtaRecibida = new byte[rtaLength];
            entrada.readFully(rtaRecibida);

            // Paso 5a: Calcular R = D(K_w+, Rta)
            byte[] retoBytes = reto.getBytes();
            byte[] retoDescifrado = CifradoUtils.descifrarRSAPublica(rtaRecibida, llavePublicaRSA);

            // Paso 5b: Verificar R == Reto
            boolean verificacionExitosa = Arrays.equals(retoBytes, retoDescifrado);

            // Paso 6: Enviar "OK" o "ERROR" según la verificación
            salida.writeUTF(verificacionExitosa ? "OK" : "ERROR");
            salida.flush();
            
            // Paso 8: Recibir G, P, G^a y firma
            // Recibir G
            int gLength = entrada.readInt();
            byte[] gBytes = new byte[gLength];
            entrada.readFully(gBytes);
            BigInteger g = new BigInteger(gBytes);
            
            // Recibir P
            int pLength = entrada.readInt();
            byte[] pBytes = new byte[pLength];
            entrada.readFully(pBytes);
            BigInteger p = new BigInteger(pBytes);
            
            // Recibir G^a
            int gALength = entrada.readInt();
            byte[] gABytes = new byte[gALength];
            entrada.readFully(gABytes);
            
            // Recibir firma F(K_w-, (G,P,G^a))
            int firmaLength = entrada.readInt();
            byte[] firma = new byte[firmaLength];
            entrada.readFully(firma);
            
            // Paso 9: Verificar firma F(K_w-, (G,P,G^a))
            ByteArrayOutputStream datosAVerificar = new ByteArrayOutputStream();
            datosAVerificar.write(gBytes);
            datosAVerificar.write(pBytes);
            datosAVerificar.write(gABytes);
            
            boolean firmaValida = CifradoUtils.verificarFirma(datosAVerificar.toByteArray(), firma, llavePublicaRSA);
            
            // Paso 10: Enviar "OK" o "ERROR" según verificación
            if (!firmaValida) {
                salida.writeUTF("ERROR");
                salida.flush();
                System.err.println("Firma inválida");
                return;
            }
            
            salida.writeUTF("OK");
            salida.flush();
            
            // Paso 11a: Calcular (G^a)^y y generar llaves de sesión
            // Crear los parámetros DH
            DHParameterSpec dhParams = new DHParameterSpec(p, g);
            
            // Generar par de llaves DH para el cliente
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(dhParams);
            KeyPair clienteDHPair = keyGen.generateKeyPair();
            
            // Reconstruir llave pública DH del servidor
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(gABytes);
            PublicKey servidorDHPublica = keyFactory.generatePublic(x509KeySpec);
            
            // Calcular secreto compartido
            byte[] secretoCompartido = CifradoUtils.calcularLlaveSecretaDH(clienteDHPair.getPrivate(), servidorDHPublica);
            
            // Generar llaves simétricas
            SecretKey[] llaves = CifradoUtils.generarLlavesSesion(secretoCompartido);
            SecretKey llaveCifrado = llaves[0]; // K_AB1
            SecretKey llaveHMAC = llaves[1];    // K_AB2
            
            // Paso 11: Enviar llave pública DH del cliente (G^y)
            byte[] clienteDHPublicaBytes = clienteDHPair.getPublic().getEncoded();
            salida.writeInt(clienteDHPublicaBytes.length);
            salida.write(clienteDHPublicaBytes);
            
            // Paso 12a: Generar IV
            byte[] iv = CifradoUtils.generarIV();
            
            // Paso 12b: Enviar IV
            salida.writeInt(iv.length);
            salida.write(iv);
            salida.flush();
            
            // Paso 13: Recibir tabla_ids_servicios cifrada y su HMAC
            int tablaCifradaLength = entrada.readInt();
            byte[] tablaCifrada = new byte[tablaCifradaLength];
            entrada.readFully(tablaCifrada);
            
            int hmacLength = entrada.readInt();
            byte[] hmacTabla = new byte[hmacLength];
            entrada.readFully(hmacTabla);
            boolean hmacValido = CifradoUtils.verificarHMAC(tablaCifrada, hmacTabla, llaveHMAC);
            if (!hmacValido) {
                System.err.println("HMAC de la tabla de servicios no válido");
                return;
            }
            
            // Descifrar la tabla de servicios
            byte[] tablaDescifrada = CifradoUtils.descifrarAES(tablaCifrada, llaveCifrado, iv);
            String tablaServicios = new String(tablaDescifrada);
            System.out.println("Tabla de servicios recibida:");
            System.out.println(tablaServicios);
            
            // Seleccionar un servicio
            Scanner scanner = new Scanner(System.in);
            System.out.println("Ingrese el ID del servicio que desea utilizar:");
            String idServicio = scanner.nextLine();
            
            // Crear mensaje con ID de servicio e IP del cliente
            String ipCliente = InetAddress.getLocalHost().getHostAddress();
            String mensaje = idServicio + "+" + ipCliente;
            
            // Paso 14: Enviar C(K_AB1, id_servicio+IP_cliente) y HMAC
            byte[] mensajeCifrado = CifradoUtils.cifrarAES(mensaje.getBytes(), llaveCifrado, iv);
            byte[] hmacMensaje = CifradoUtils.generarHMAC(mensajeCifrado, llaveHMAC);
            
            salida.writeInt(mensajeCifrado.length);
            salida.write(mensajeCifrado);
            salida.writeInt(hmacMensaje.length);
            salida.write(hmacMensaje);
            salida.flush();
            
            // Paso 15: El servidor verifica el HMAC y responde
            
            // Paso 16: Recibir datos del servidor deseado (ip_servidor+puerto_servidor)
            int datosCifradosLength = entrada.readInt();
            byte[] datosCifrados = new byte[datosCifradosLength];
            entrada.readFully(datosCifrados);
            
            int hmacDatosLength = entrada.readInt();
            byte[] hmacDatos = new byte[hmacDatosLength];
            entrada.readFully(hmacDatos);
            
            // Paso 17: Verificar HMAC de los datos recibidos
            boolean hmacDatosValido = CifradoUtils.verificarHMAC(datosCifrados, hmacDatos, llaveHMAC);
            if (!hmacDatosValido) {
                System.err.println("HMAC de los datos del servidor no válido");
                return;
            }
            
            // Descifrar datos del servidor
            byte[] datosDescifrados = CifradoUtils.descifrarAES(datosCifrados, llaveCifrado, iv);
            String datosServidor = new String(datosDescifrados);
            String[] partes = datosServidor.split("\\+");
            if (partes.length != 2) {
                System.err.println("Formato de datos del servidor incorrecto");
                return;
            }
            
            String ipServidor = partes[0];
            int puertoServidor;
            try {
                puertoServidor = Integer.parseInt(partes[1]);
            } catch (NumberFormatException e) {
                System.err.println("Formato de puerto incorrecto");
                return;
            }
            
            // Paso 18: Enviar "OK" si todo está correcto
            salida.writeUTF("OK");
            salida.flush();
            
            System.out.println("Conexión establecida correctamente con el servidor principal");
            System.out.println("Datos del servidor de servicio: " + ipServidor + ":" + puertoServidor);
            
            // Ahora podemos conectarnos al servidor de servicio
            System.out.println("¿Desea conectarse al servidor de servicio? (S/N)");
            String respuesta = scanner.nextLine();
            
            if (respuesta.equalsIgnoreCase("S")) {
                conectarAlServidorDeServicio(ipServidor, puertoServidor, llaveCifrado, llaveHMAC, iv);
            } else {
                System.out.println("Operación cancelada");
            }
            
        } catch (Exception e) {
            System.err.println("Error durante la comunicación con el servidor:");
            e.printStackTrace();
        }
    }
    
    private static void cargarLlavePublica() {
        try {
            // Cargar llave pública RSA del servidor desde un archivo
            File archivoLlave = new File("servidor_publica.key");
            FileInputStream fis = new FileInputStream(archivoLlave);
            byte[] keyBytes = new byte[(int) archivoLlave.length()];
            fis.read(keyBytes);
            fis.close();
            
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            llavePublicaRSA = kf.generatePublic(spec);
            
            System.out.println("Llave pública RSA del servidor cargada correctamente");
        } catch (Exception e) {
            System.err.println("Error al cargar la llave pública del servidor:");
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    private static void conectarAlServidorDeServicio(String ip, int puerto, SecretKey llaveCifrado, 
                                                    SecretKey llaveHMAC, byte[] iv) {
        try (Socket socket = new Socket(ip, puerto);
             DataInputStream entrada = new DataInputStream(socket.getInputStream());
             DataOutputStream salida = new DataOutputStream(socket.getOutputStream())) {
            
            System.out.println("Conectado al servidor de servicio: " + ip + ":" + puerto);
            
            // Aquí implementaríamos la comunicación con el servidor de servicio
            // Esta parte dependería de la especificación del protocolo para el servidor de servicio
            
            // Por ejemplo, podríamos enviar un mensaje cifrado para iniciar la comunicación
            String mensajeInicial = "INICIO_SERVICIO";
            byte[] mensajeCifrado = CifradoUtils.cifrarAES(mensajeInicial.getBytes(), llaveCifrado, iv);
            byte[] hmacMensaje = CifradoUtils.generarHMAC(mensajeCifrado, llaveHMAC);
            
            salida.writeInt(mensajeCifrado.length);
            salida.write(mensajeCifrado);
            salida.writeInt(hmacMensaje.length);
            salida.write(hmacMensaje);
            salida.flush();
            
            // Luego recibir la respuesta
            int respuestaCifradaLength = entrada.readInt();
            byte[] respuestaCifrada = new byte[respuestaCifradaLength];
            entrada.readFully(respuestaCifrada);
            
            int hmacRespuestaLength = entrada.readInt();
            byte[] hmacRespuesta = new byte[hmacRespuestaLength];
            entrada.readFully(hmacRespuesta);
            
            // Verificar HMAC
            boolean hmacRespuestaValido = CifradoUtils.verificarHMAC(respuestaCifrada, hmacRespuesta, llaveHMAC);
            if (!hmacRespuestaValido) {
                System.err.println("HMAC de la respuesta del servidor de servicio no válido");
                return;
            }
            
            // Descifrar respuesta
            byte[] respuestaDescifrada = CifradoUtils.descifrarAES(respuestaCifrada, llaveCifrado, iv);
            String respuestaServidor = new String(respuestaDescifrada);
            
            System.out.println("Respuesta del servidor de servicio: " + respuestaServidor);
            
            // Implementar el resto de la comunicación con el servidor de servicio según el protocolo
            
        } catch (Exception e) {
            System.err.println("Error durante la comunicación con el servidor de servicio:");
            e.printStackTrace();
        }
    }
}
