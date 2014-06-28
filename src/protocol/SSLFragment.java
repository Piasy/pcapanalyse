package protocol;

import java.util.ArrayList;

public class SSLFragment
{
	ArrayList<SockPacket> packets;
	public SSLFragment(ArrayList<SockPacket> ps)
	{
		packets = ps;
	}
	
	
	double start = -1, end = -1;
	public void calc()
	{
		for (SockPacket p : packets)
		{
			if (start == -1)
			{
				start = p.time;
				end = p.time;
			}
			else
			{
//				if
			}
		}
	}
	
	@Override
	public String toString()
	{
		String ret = "";
		

//		for (SockPacket p : f.packets)
//		{
//			System.out.println("\t\t" + p);
//		}
		
		return ret;
	}
}
