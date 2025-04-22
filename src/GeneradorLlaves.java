import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

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
            
            // Guardar las llaves en archivos
            try (FileOutputStream fos = new FileOutputStream("public.key")) {
                fos.write(publicKey.getEncoded());
            }
            
            try (FileOutputStream fos = new FileOutputStream("private.key")) {
                fos.write(privateKey.getEncoded());
            }
            
            System.out.println("Llaves generadas exitosamente.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}