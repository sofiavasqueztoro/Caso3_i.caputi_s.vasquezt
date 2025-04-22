public class Servicio {
    private String nombre;
    private String identificador;
    private String ip;
    private int puerto;
    
    public Servicio(String nombre, String identificador, String ip, int puerto) {
        this.nombre = nombre;
        this.identificador = identificador;
        this.ip = ip;
        this.puerto = puerto;
    }
    
    // Getters
    public String getNombre() { return nombre; }
    public String getIdentificador() { return identificador; }
    public String getIp() { return ip; }
    public int getPuerto() { return puerto; }
    
    @Override
    public String toString() {
        return identificador + ":" + nombre;
    }
}