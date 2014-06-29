package protocol;

import java.util.ArrayList;

public class SSLFragment
{
	ArrayList<SockPacket> packets;
	public SSLFragment(ArrayList<SockPacket> ps)
	{
		packets = ps;
	}
	
	
	public double start = -1, end = -1;
	
	@Override
	public String toString()
	{
		String ret = "Fragment: start = " + start + ", end = " + end + "\n";
		
		for (SockPacket p : packets)
		{
			ret += "\t\t" + p.toString() + "\n";
		}
		
		return ret;
	}
}
