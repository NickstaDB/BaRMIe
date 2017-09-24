package nb.barmie.modes.enumeration;

import java.util.ArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import nb.barmie.modes.attack.RMIAttackFactory;
import nb.barmie.net.TCPEndpoint;
import nb.barmie.util.ProgramOptions;

/***********************************************************
 * Enumeration mode - spawns EnumerationTask objects to
 * enumerate each target and print out the enumeration
 * results.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class EnumerationMode {
	/*******************
	 * Properties
	 ******************/
	private ProgramOptions _opts;
	
	/*******************
	 * Construct the enumeration mode object.
	 * 
	 * @param options The program options.
	 ******************/
	public EnumerationMode(ProgramOptions options) {
		this._opts = options;
	}
	
	/*******************
	 * Enumeration mode main function.
	 ******************/
	public void run() {
		ThreadPoolExecutor tpe = (ThreadPoolExecutor)Executors.newFixedThreadPool(this._opts.getThreadCount());
		ArrayList<TCPEndpoint> targets = this._opts.getTargets();
		RMIEnumerator rmie = new RMIEnumerator(this._opts);
		
		//Initialise the list of known attacks with the current program options
		RMIAttackFactory.setProgramOptions(this._opts);
		
		//Status
		System.out.println("Scanning " + targets.size() + " target(s) for objects exposed via an RMI registry...");
		System.out.println("");
		
		//Pass all tasks to the thread pool executor
		for(TCPEndpoint t: targets) {
			tpe.execute(new EnumerationTask(t, rmie, this._opts));
		}
		
		//Shutdown the thread pool and wait for threads to finish executing
		tpe.shutdown();
		while(tpe.isTerminated() == false) { }
		
		//Done
		System.out.println("Successfully scanned " + targets.size() + " target(s) for objects exposed via RMI.");
		
		//Clean up all attacks (e.g. stop proxies that were started to enumerate endpoints)
		RMIAttackFactory.cleanUp();
	}
}
