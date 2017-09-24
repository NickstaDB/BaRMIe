package org.springframework.remoting.rmi;

import java.rmi.RemoteException;
import java.rmi.server.RemoteStub;
import org.springframework.remoting.support.RemoteInvocation;

/***********************************************************
 * RmiInvocationHandler stub for Spring Framework 2
 * attacks.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class RmiInvocationWrapper_Stub extends RemoteStub implements RmiInvocationHandler {
	//Dummy serialVersionUID
	public static final long serialVersionUID = 2L;
	
	/*******************
	 * Stub to call the remote invoke() method.
	 ******************/
	public Object invoke(RemoteInvocation ri) throws RemoteException {
		try {
			Object result = this.ref.invoke(this, RmiInvocationHandler.class.getMethod("invoke", new Class[] {RemoteInvocation.class}), new Object[] { ri }, -5752512342587169831L);
			return result;
		} catch(RuntimeException | RemoteException ex1) {
			throw ex1;
		} catch(Exception ex2) {
			throw new RemoteException("Unexpected exception.", ex2);
		}
	}
}
