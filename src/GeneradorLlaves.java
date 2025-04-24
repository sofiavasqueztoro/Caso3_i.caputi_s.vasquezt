import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class GeneradorLlaves {
    public static void main(String[] args) {
        try {
            // Generar par de llaves RSA
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair pair = keyGen.generateKeyPair();
            
            // Obtener las llaves pública y privada
            PublicKey publicKey = pair.getPublic();
            PrivateKey privateKey = pair.getPrivate();
            
            // Codificar las llaves en Base64 para almacenamiento en texto
            String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            String privateKeyBase64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());
            
            // Guardar las llaves en archivos .txt
            try (FileOutputStream fos = new FileOutputStream("public.txt")) {
                fos.write(publicKeyBase64.getBytes());
            }
            
            try (FileOutputStream fos = new FileOutputStream("private.txt")) {
                fos.write(privateKeyBase64.getBytes());
            }
            
            System.out.println("Llaves generadas y guardadas exitosamente en formato .txt.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
