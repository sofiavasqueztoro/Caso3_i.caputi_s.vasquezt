import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import javax.crypto.SecretKey;
import javax.crypto.spec.*;

public class Cliente extends Thread {
    private static final String HOST_SERVIDOR = "localhost";
    private static final int PUERTO_SERVIDOR = 5000;
    private static PublicKey llavePublicaRSA;
    private static final Scanner scannerGlobal = new Scanner(System.in);
    private final int clientId;

    public Cliente(int id) {
        this.clientId = id;
    }

    
    public static void main(String[] args) {
        System.out.print("Por favor, introduzca la cantidad de clientes que desea ejecutar:\n> ");
        int numClientes = scannerGlobal.nextInt();
        
        int i = 1; 
        while (i <= numClientes) {
            Cliente cliente = new Cliente(i);
            cliente.start();

            i++;
        }

    }

    public void run() {
        try {

            System.out.println("Cliente " + clientId + " iniciando conexión...");

            try (Socket socket = new Socket(HOST_SERVIDOR, PUERTO_SERVIDOR);
             DataInputStream entrada = new DataInputStream(socket.getInputStream());
             DataOutputStream salida = new DataOutputStream(socket.getOutputStream())) {


            // Paso 0b: Cargar llave pública RSA del servidor
            cargarLlavePublica();
            System.out.println("0a. Se leyo la llave publica de archivo exitosamente.");
            
            System.out.println("Conectado al servidor principal: " + HOST_SERVIDOR + ":" + PUERTO_SERVIDOR);
            
            // Paso 1: Enviar "HELLO"
            salida.writeUTF("HELLO");
            System.out.println("1. Se envio HELLO a servidor exitosamente.");
            salida.flush();


            // Paso 2a: Generar un reto aleatorio
            String reto = CifradoUtils.generarReto();
            System.out.println("2a. Reto generado exitosamente: " + reto);

            // Paso 2b: Enviar el reto al servidor
            salida.writeUTF(reto);
            salida.flush();
            System.out.println("2b. Se envio Reto a Servidor.");

            // Paso 4: Recibir Rta del servidor
            int rtaLength = entrada.readInt();
            byte[] rtaRecibida = new byte[rtaLength];
            entrada.readFully(rtaRecibida);
            System.out.println("4. Recibio correctamente Rta del Servidor.");

            // Paso 5a: Calcular R = D(K_w+, Rta)
            byte[] retoBytes = reto.getBytes();
            byte[] retoDescifrado = CifradoUtils.descifrarRSAPublica(rtaRecibida, llavePublicaRSA);
            System.out.println("5a. Se calculo R = D(K_w+, Rta) correctamente.");

            // Paso 5b: Verificar R == Reto
            boolean verificacionExitosa = Arrays.equals(retoBytes, retoDescifrado);
            System.out.println("5b. Se  verifico R == Reto correctamente");

            // Paso 6: Enviar "OK" o "ERROR" según la verificación
            salida.writeUTF(verificacionExitosa ? "OK" : "ERROR");
            salida.flush();
            if(verificacionExitosa){
                System.out.println("6. Se  envio 'OK' correctamente al servidor");
            }else{
                System.out.println("6. Se  envio 'ERROR' correctamente al servidor");
            }
            
            
            // Paso 8: Recibir G, P, G^x y firma
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

            
            // Recibir firma F(K_w-, (G,P,G^x))
            int firmaLength = entrada.readInt();
            byte[] firma = new byte[firmaLength];
            entrada.readFully(firma);

            System.out.println("8. Se recibio G, P, G^x y firma F(K_w-, (G,P,G^x)) del servidor correctamente");
            
            // Paso 9: Verificar firma F(K_w-, (G,P,G^a))
            ByteArrayOutputStream datosAVerificar = new ByteArrayOutputStream();
            datosAVerificar.write(gBytes);
            datosAVerificar.write(pBytes);
            datosAVerificar.write(gABytes);
            
            boolean firmaValida = CifradoUtils.verificarFirma(datosAVerificar.toByteArray(), firma, llavePublicaRSA);
            
            System.out.println("9. Se verifico firma F(K_w-, (G,P,G^a)) correctamente");
            // Paso 10: Enviar "OK" o "ERROR" según verificación
            if (!firmaValida) {
                salida.writeUTF("ERROR");
                salida.flush();
                System.err.println("10. Se envio 'ERROR' a servidor, firma inválida");
                return;
            }
            
            salida.writeUTF("OK");
            salida.flush();
            System.out.println("10. Se envio 'OK' a servidor exitosamente");
            
            // Paso 11a: Calcular (G^x)^y y generar llaves de sesión
            // parámetros DH
            DHParameterSpec dhParams = new DHParameterSpec(p, g);
            
            // llaves DH para el cliente
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(dhParams);
            KeyPair clienteDHPair = keyGen.generateKeyPair();
            
            // Reconstruir llave pública DH del servidor
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(gABytes);
            PublicKey servidorDHPublica = keyFactory.generatePublic(x509KeySpec);
            byte[] secretoCompartido = CifradoUtils.calcularLlaveSecretaDH(clienteDHPair.getPrivate(), servidorDHPublica);
            
            // Generar llaves simétricas
            SecretKey[] llaves = CifradoUtils.generarLlavesSesion(secretoCompartido);
            SecretKey llaveCifrado = llaves[0]; // K_AB1
            SecretKey llaveHMAC = llaves[1];    // K_AB2

            System.out.println("11a. Se calculo (G^x)^y y se generaron las llaves simetricas K_AB1 y K_AB2");
            
            // Paso 11: Enviar G^y
            byte[] clienteDHPublicaBytes = clienteDHPair.getPublic().getEncoded();
            salida.writeInt(clienteDHPublicaBytes.length);
            salida.write(clienteDHPublicaBytes);
            System.out.println("11a. Se envio la llave G^y correctamente");
            
            // Paso 12a: Generar IV
            byte[] iv = CifradoUtils.generarIV();
            System.out.println("12a. Se genero IV correctamente");
            
            // Paso 12b: Enviar IV
            salida.writeInt(iv.length);
            salida.write(iv);
            salida.flush();
            System.out.println("12a. Se envio IV a Servidor correctamente");
            
            // Paso 13: Recibir tabla_ids_servicios cifrada y su HMAC
            int tablaCifradaLength = entrada.readInt();
            byte[] tablaCifrada = new byte[tablaCifradaLength];
            entrada.readFully(tablaCifrada);
            System.out.println("13.Tabla de servicios recibida correctamente");
            
            int hmacLength = entrada.readInt();
            byte[] hmacTabla = new byte[hmacLength];
            entrada.readFully(hmacTabla);
            boolean hmacValido = CifradoUtils.verificarHMAC(tablaCifrada, hmacTabla, llaveHMAC);
            if (!hmacValido) {
                System.err.println("13b. El HMAC de la tabla de servicios no es válido");
                return;
            }
            System.out.println("13b. Se verifico el HMAC de la tabla de servicios correctamente");
            
            // Descifrar la tabla de servicios
            byte[] tablaDescifrada = CifradoUtils.descifrarAES(tablaCifrada, llaveCifrado, iv);
            String tablaServicios = new String(tablaDescifrada);
            System.out.println("Tabla de servicios:");
            System.out.println(tablaServicios);
            
            // Seleccionar un servicio
            Random random = new Random();
            int numeroAleatorio = random.nextInt(3) + 1; 
            String idServicio = "S"+String.valueOf(numeroAleatorio);
            System.out.println("Se selecciono el servicio "+idServicio+" correctamente.");
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
            System.out.println("14. Se envio C(K_AB1, id_servicio+IP_cliente) y HMAC correctamente");
            
            // Paso 16: Recibir C(K_AB1, id_servicio+puerto_servidor) y HMAC 
            int datosCifradosLength = entrada.readInt();
            byte[] datosCifrados = new byte[datosCifradosLength];
            entrada.readFully(datosCifrados);
            
            int hmacDatosLength = entrada.readInt();
            byte[] hmacDatos = new byte[hmacDatosLength];
            entrada.readFully(hmacDatos);

            System.out.println("16. Recibio C(K_AB1, id_servicio+puerto_servidor) y HMAC correctamente");
            
            // Paso 17: Verificar HMAC de los datos recibidos
            boolean hmacDatosValido = CifradoUtils.verificarHMAC(datosCifrados, hmacDatos, llaveHMAC);
            if (!hmacDatosValido) {
                System.err.println("17. HMAC de los datos del servidor no válido");
                return;
            }

            System.out.println("17. Verifica HMAC correctamente");
            
            // Descifrar datos del servidor
            byte[] datosDescifrados = CifradoUtils.descifrarAES(datosCifrados, llaveCifrado, iv);
            String datosServidor = new String(datosDescifrados);
            String[] partes = datosServidor.split("\\+");
            if (partes.length != 2) {
                System.err.println("18. Se envio ERROR al servidor: Formato de datos del servidor incorrecto");
                salida.writeUTF("ERROR");
                salida.flush();
                return;
            }
            
            String ipServidor = partes[0];
            int puertoServidor;
            try {
                puertoServidor = Integer.parseInt(partes[1]);
            } catch (NumberFormatException e) {
                System.err.println("18. Se envio ERROR al servidor:Formato de puerto incorrecto");
                salida.writeUTF("ERROR");
                salida.flush();
                return;
            }
            
            // Paso 18: Enviar "OK" si todo está correcto
            salida.writeUTF("OK");
            salida.flush();
            System.out.println("18. Se envio 'OK' correctamente al servidor.");
            
            System.out.println("Conexión establecida correctamente con el servidor principal");
            System.out.println("Datos del servidor de servicio: " + ipServidor + ":" + puertoServidor);
            
            
            
        } catch (Exception e) {
            System.err.println("Error durante la comunicación con el servidor:");
            e.printStackTrace();
        }
    
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    
    private static void cargarLlavePublica() {
        try {
            // Cargar y decodificar llave pública RSA desde archivo .txt
            String publicKeyBase64 = new String(Files.readAllBytes(Paths.get("public.txt")));
            byte[] decodedPublicKey = Base64.getDecoder().decode(publicKeyBase64);
            
            // Crear la llave pública a partir de los datos decodificados
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedPublicKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            llavePublicaRSA = kf.generatePublic(spec);
            
            System.out.println("Llave pública RSA del servidor cargada correctamente");
        } catch (Exception e) {
            System.err.println("Error al cargar la llave pública del servidor:");
            e.printStackTrace();
            System.exit(1);
        }
    }
    
}
