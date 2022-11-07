package seguridad20222_cliente;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import seguridad20222_servidor.SecurityFunctions;

public class ThreadCliente extends Thread{
	
	private Socket socket;
	private BigInteger p;
	private BigInteger g;
	private SecurityFunctions f;
	private int idC;
	
	
	
	public ThreadCliente(int idC, Socket socket) {
		this.socket = socket;
		this.idC = idC;
		
	}
	
	public void run() {
		
		try {
			PrintWriter ac = new PrintWriter(socket.getOutputStream() , true);
			BufferedReader dc = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			f = new SecurityFunctions();
			
			ac.println("SECURE INIT");
			
			SecureRandom r = new SecureRandom();
			int x = Math.abs(r.nextInt());
			Long longx = Long.valueOf(x);
    		BigInteger bix = BigInteger.valueOf(longx);
			
			String gStr = dc.readLine();
			String pStr = dc.readLine();
			String gxStr = dc.readLine();
			
			// recibe los valores de g, p y Gx
			this.g = new BigInteger(gStr);
			this.p = new BigInteger(pStr);
			BigInteger gx = new BigInteger(gxStr);
			
			// Recibe la firma del servidor
			String firmaStr = dc.readLine();
			byte[] firma = str2byte(firmaStr);
				
			// Conoce la llave pública del servidor
			PublicKey publicaServidor = f.read_kplus("datos_asim_srv.pub", String.valueOf(idC));
			
			// Verificar la firma del servidor
			String msj = gStr+","+pStr+","+gxStr;
			
			if(f.checkSignature(publicaServidor, firma, msj)) {
				
				ac.println("OK");
				
				// Crea el valor Gy para enviar al servidor
				BigInteger valorComun = G2X(g, bix, p);
				String strValorComun = valorComun.toString();
				ac.println(strValorComun);
				
				// Calcula la llave maestra usando gx
				BigInteger llaveMaestra = calcularLlaveMaestra(gx, bix, this.p);
				String strLlaveMaestra = llaveMaestra.toString();
				System.out.println(this.idC + "llave maestra: " + strLlaveMaestra);
				
				// Generar la llave simétrica K_AB1
				SecretKey skSrv = f.csk1(strLlaveMaestra);
				
				// Generar la llave simétrica K_AB2
				SecretKey skMac = f.csk2(strLlaveMaestra);
				
				// Generar el iv1
				byte[] iv1 = generateIvBytes();
				String striv1 = byte2str(iv1);
				IvParameterSpec ivSpec1 = new IvParameterSpec(iv1);
				
				// Creación y envío de mensajes al servidor
				int consultaInt = Math.abs(r.nextInt());
				String strConsulta = Integer.toString(consultaInt);
				byte[] byteConsulta = strConsulta.getBytes();
				byte[] consulta = f.senc(byteConsulta, skSrv, ivSpec1, Integer.toString(this.idC));
				byte[] consultaMac = f.hmac(byteConsulta, skMac);
				
				String m1 = byte2str(consulta);
				String m2 = byte2str(consultaMac);
				ac.println(m1);
				ac.println(m2);
				ac.println(striv1);
				
				// Verificar si la prueba de integridad pasó
				String verificacion = dc.readLine();
				
				if(verificacion.compareTo("ERROR")==0) {
					System.out.println("==========> Fallo de integridad: La query y la mac no coinciden");
					System.out.println("Testeo de cliente-servidor: fallo");
					socket.close();
				}
				
				else if(verificacion.compareTo("OK")==0) {
					
					// Recibe los mensajes enviados del servidor
					String respuesta = dc.readLine();
					String macRespuesta = dc.readLine();
					String iv2Str = dc.readLine();
					
					byte[] byteRespuesta = str2byte(respuesta);
					byte[] byteMacRespuesta = str2byte(macRespuesta);
					byte[] iv2 = str2byte(iv2Str);
					IvParameterSpec ivSpec2 = new IvParameterSpec(iv2);
					
					// Hace la prueba de integridad
					byte[] msjDescifrado = f.sdec(byteRespuesta, skSrv, ivSpec2);
					boolean confirmacion = f.checkInt(msjDescifrado, skMac, byteMacRespuesta);
					System.out.println("Cliente " + idC+" - " + "Testeo  de integridad: " + confirmacion);
					
					if(confirmacion) {
						ac.println("OK");
					}
					else {
						ac.println("ERROR");
						System.out.println("Testeo de cliente-servidor: fallo");
					}
					socket.close();
				}
				
			}
			else {
				ac.println("ERROR");
				System.out.println("==========> Fallo de autenticidad: La firma digital no es la correcta");
				System.out.println("Testeo de cliente-servidor: fallo");
				socket.close();
			}	
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private BigInteger G2X(BigInteger base, BigInteger exponente, BigInteger modulo) {
		return base.modPow(exponente,modulo);
	}
	
	private BigInteger calcularLlaveMaestra(BigInteger base, BigInteger exponente, BigInteger modulo) {
		return base.modPow(exponente, modulo);
	}
	
	private byte[] generateIvBytes() {
	    byte[] iv = new byte[16];
	    new SecureRandom().nextBytes(iv);
	    return iv;
	}
	
	public byte[] str2byte( String ss)
	{	
		// Encapsulamiento con hexadecimales
		byte[] ret = new byte[ss.length()/2];
		for (int i = 0 ; i < ret.length ; i++) {
			ret[i] = (byte) Integer.parseInt(ss.substring(i*2,(i+1)*2), 16);
		}
		return ret;
	}
	
	public String byte2str( byte[] b )
	{	
		// Encapsulamiento con hexadecimales
		String ret = "";
		for (int i = 0 ; i < b.length ; i++) {
			String g = Integer.toHexString(((char)b[i])&0x00ff);
			ret += (g.length()==1?"0":"") + g;
		}
		return ret;
	}

}
