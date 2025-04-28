import java.security.*;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.*;
import javax.crypto.spec.*;

public class CifradoUtils {
    //definimos los algoritmos
    private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String RSA_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String DH_ALGORITHM = "DiffieHellman";
    private static final int IV_LENGTH = 16;
    
    //Función que genera un reto aleatorio
    public static String generarReto() {
        Random random = new SecureRandom();
        return String.valueOf(Math.abs(random.nextLong()));
    }
    
    // Función para cifrar con RSA usando la llave privada
    public static byte[] cifrarRSAPrivada(byte[] datos, PrivateKey llave) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, llave);
        return cipher.doFinal(datos);
    }

    //Función para cifrar con RSA usando la llave publica
    public static byte[] cifrarRSAPublica(byte[] datos, PublicKey llave) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, llave);
        return cipher.doFinal(datos);
    }
    
    // Función para descifrar con RSA usando la llave pública
    public static byte[] descifrarRSAPublica(byte[] datosCifrados, PublicKey llave) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, llave);
        return cipher.doFinal(datosCifrados);
    }
    
    // Generar parámetros de Diffie-Hellman
    public static DHParameterSpec generarParametrosDH() throws Exception {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance(DH_ALGORITHM);
        paramGen.init(1024);
        AlgorithmParameters params = paramGen.generateParameters();
        return params.getParameterSpec(DHParameterSpec.class);
    }
    
    // Generar par de llaves Diffie-Hellman
    public static KeyPair generarParLlavesDH(DHParameterSpec dhSpec) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(DH_ALGORITHM);
        keyGen.initialize(dhSpec);
        return keyGen.generateKeyPair();
    }
    
    // Calcular llave secreta compartida Diffie-Hellman
    public static byte[] calcularLlaveSecretaDH(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance(DH_ALGORITHM);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }
    
    // Función para firmar datos con RSA
    public static byte[] firmar(byte[] datos, PrivateKey llave) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(llave);
        signature.update(datos);
        return signature.sign();
    }
    
    // Función para verificar firma RSA
    public static boolean verificarFirma(byte[] datos, byte[] firma, PublicKey llave) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(llave);
        signature.update(datos);
        return signature.verify(firma);
    }
    
    // Función para cifrar datos con AES
    public static byte[] cifrarAES(byte[] datos, SecretKey llave, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, llave, ivSpec);
        return cipher.doFinal(datos);
    }
    
    // Función para descifrar datos con AES
    public static byte[] descifrarAES(byte[] datosCifrados, SecretKey llave, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, llave, ivSpec);
        return cipher.doFinal(datosCifrados);
    }
    
    // Función para generar código HMAC
    public static byte[] generarHMAC(byte[] datos, SecretKey llave) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(llave);
        return mac.doFinal(datos);
    }
    
    // Función para verificar código HMAC
    public static boolean verificarHMAC(byte[] datos, byte[] hmacRecibido, SecretKey llave) throws Exception {
        byte[] hmacCalculado = generarHMAC(datos, llave);
        return MessageDigest.isEqual(hmacCalculado, hmacRecibido);
    }
    
    // Función para generar un IV aleatorio
    public static byte[] generarIV() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        return iv;
    }
    
    // Función para generar llaves de sesión a partir de un secreto compartido
    public static SecretKey[] generarLlavesSesion(byte[] secretoCompartido) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] hashedKey = digest.digest(secretoCompartido);
        
        // Dividir en dos partes: una para cifrado y otra para HMAC
        byte[] aesPart = Arrays.copyOfRange(hashedKey, 0, 32); // Primeros 256 bits
        byte[] hmacPart = Arrays.copyOfRange(hashedKey, 32, 64); // Últimos 256 bits
        
        // Crear las llaves secretas
        SecretKey aesKey = new SecretKeySpec(aesPart, "AES");
        SecretKey hmacKey = new SecretKeySpec(hmacPart, HMAC_ALGORITHM);
        
        return new SecretKey[] {aesKey, hmacKey};
    }
}
