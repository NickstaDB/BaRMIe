package org.springframework.remoting.rmi;

import java.rmi.Remote;
import java.rmi.RemoteException;
import org.springframework.remoting.support.RemoteInvocation;

/***********************************************************
 * RmiInvocationHandler interface for Spring Framework
 * attacks.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public interface RmiInvocationHandler extends Remote {
	public Object invoke(RemoteInvocation invocation) throws RemoteException;
}
