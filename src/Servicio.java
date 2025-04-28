public class Servicio {
    private String nombre;
    private String identificador;
    private String ip;
    private int puerto;
    //cada servicio creado en el servidor debe tener un nombre, un identificador, una ip y un puerto
    public Servicio(String nombre, String identificador, String ip, int puerto) {
        this.nombre = nombre;
        this.identificador = identificador;
        this.ip = ip;
        this.puerto = puerto;
    }
    //para retornar la respuesta del servicio seleccionado por un cliente se debe enviar su IP y su puerto respectivo
    public String getIp() { return ip; }
    public int getPuerto() { return puerto; }
    
    @Override
    public String toString() {
        return identificador + ":" + nombre;
    }
}