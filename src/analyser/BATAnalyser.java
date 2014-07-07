package analyser;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.util.ArrayList;

public class BATAnalyser
{

	public static void main(String[] args)
	{
		ArrayList<ArrayList<Float>> goodputs = new ArrayList<ArrayList<Float>>();
		File pwd = new File(".");
		File[] files = pwd.listFiles();
		for (File f : files)
		{
			if (f.isDirectory())
			{
				Analyser analyser = new Analyser(f);
				File trace = new File(f.getAbsolutePath() + "/trace.pcap");
				File connsLog = new File(f.getAbsolutePath() + "/connection_log.csv");
				analyser.analyse(trace, connsLog);
				goodputs.addAll(analyser.getAllGoodputs());
			}
		}
		try
		{
			PrintStream out = new PrintStream(new File(pwd.getAbsolutePath() + "/gps.csv"));
			for (ArrayList<Float> gp : goodputs)
			{
				out.println(((gp.get(0) > 0) ? gp.get(0) : Float.NaN) + "," + ((gp.get(1) > 0) ? gp.get(1) : Float.NaN));
			}			
			out.close();
		}
		catch (FileNotFoundException e)
		{
			e.printStackTrace();
		}
	}

}
