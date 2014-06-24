package protocol;

import java.util.ArrayList;

import util.Util;

public class DNSRecord
{

	public String name;
	public ArrayList<String> middle;
//	public int ip;
	public ArrayList<Integer> ips = new ArrayList<Integer>();
	public double time;

	public ArrayList<SockPacket> packets = new ArrayList<SockPacket>();
	public ArrayList<Connection> conns = new ArrayList<Connection>();
	
	
	@Override
	public boolean equals(Object obj)
	{
		boolean ret = false;
		if (obj instanceof DNSRecord)
		{
			ret = ((DNSRecord) obj).name.equals(name);// && ((DNSRecord) obj).ip == ip; //only use domain name
		}
		return ret;
	}
	
	@Override
	public int hashCode()
	{
		int ret = 0;
		for (int i = 0; i < name.length(); i ++)
		{
			ret += ((int) name.charAt(i)) * (i + 1);
		}
		return ret;
	}
	
	@Override
	public String toString()
	{
		String ret = "";
		ret += "DNS record: name = " + name;
		if (middle.size() != 0)
		{
			ret += "\n\tmiddle results:";
			for (String ss : middle)
			{
				ret += "\n\t\t" + ss;
			}
		}
		ret += "\n\tip results:";
		for (Integer ip : ips)
		{
			 ret += Util.ipInt2Str(ip) + "\t";
		}
		return ret;
	}
	
	public static boolean belongsTo(DNSRecord record, SockPacket packet)
	{
		boolean ret = false;
		for (Integer ip : record.ips)
		{
			ret = ret || ip == packet.srcIP || ip == packet.dstIP;
			if (ret)
			{
				break;
			}
		}
		return ret;
	}
}
