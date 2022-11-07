package seguridad20222_cliente;

import java.io.IOException;
import java.net.Socket;

public class ClienteMain {
	
	public static void main(String[] args) throws IOException {
		
		int puerto = 4030;
		int idThreadCliente = 0;
			
			//while(idThreadCliente < 4) {
				try {
				
				System.out.println("Se crea el nuevo socket del cliente");
				Socket socketCliente = new Socket("localhost", puerto);
				System.out.println("Se ha conectado a: " + socketCliente.getRemoteSocketAddress());
			
			
				ThreadCliente cliente = new ThreadCliente(idThreadCliente, socketCliente);
				cliente.start();
				}
				
				catch(IOException e) {
					System.out.println("Cliente " + idThreadCliente + ": connecting to server - ERROR");
					e.printStackTrace();
					
				}
				
				idThreadCliente++;
				
			
			//}
			
			
		}
	

}
