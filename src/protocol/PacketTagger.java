package protocol;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.regex.Pattern;

public class PacketTagger
{
	public HashMap<String, ArrayList<Connection>> 
	tagConnByDNS(ArrayList<Connection> conns, ArrayList<DNSRecord> records)
	{
		HashMap<String, ArrayList<Connection>> ret = new HashMap<String, ArrayList<Connection>>();
		

		ArrayList<Connection> clientX = new ArrayList<Connection>();
		ArrayList<Connection> dl_clientX = new ArrayList<Connection>();
		ArrayList<Connection> notifyX = new ArrayList<Connection>();
		ArrayList<Connection> client_lb = new ArrayList<Connection>();
		ArrayList<Connection> d_dropbox = new ArrayList<Connection>();
		ArrayList<Connection> api_dropbox = new ArrayList<Connection>();
		ArrayList<Connection> api_notify = new ArrayList<Connection>();
		ArrayList<Connection> api_content = new ArrayList<Connection>();
		Pattern clientP = Pattern.compile("^client\\d*\\.dropbox\\.com$");
		//Pattern dl_clientP = Pattern.compile("^dl-client\\d*\\.dropbox\\.com$");
		Pattern dl_clientP = Pattern.compile("^dl-.+\\d*\\.dropbox\\.com$");
		Pattern notifyP = Pattern.compile("^notify\\d*\\.dropbox\\.com$");
		
		for (Connection conn : conns)
		{
			if (conn.packets.size() > 0)
			{
				DNSRecord lastRecord = null;
				for (DNSRecord record : records)
				{
					if (DNSRecord.belongsTo(record, conn.packets.get(0)))
					{
						lastRecord = record;
					}
				}
				
				if (lastRecord != null)
				{
					if (clientP.matcher(lastRecord.name).find())
					{
						clientX.add(conn);
					}
					else if (dl_clientP.matcher(lastRecord.name).find())
					{
						dl_clientX.add(conn);
					}
					else if (notifyP.matcher(lastRecord.name).find())
					{
						notifyX.add(conn);
					}
					else if (lastRecord.name.equals("client-lb.dropbox.com"))
					{
						client_lb.add(conn);
					}
					else if (lastRecord.name.equals("d.dropbox.com"))
					{
						d_dropbox.add(conn);
					}
					else if (lastRecord.name.equals("api-content.dropbox.com"))
					{
						api_content.add(conn);
					}
					else if (lastRecord.name.equals("api.dropbox.com"))
					{
						api_dropbox.add(conn);
					}
					else if (lastRecord.name.equals("api-notify.dropbox.com"))
					{
						api_notify.add(conn);
					}
				}
			}
		}
		
		ret.put("clientX.dropbox.com", clientX);
		ret.put("dl-clientX.dropbox.com", dl_clientX);
		ret.put("client-lb.dropbox.com", client_lb);
		ret.put("notifyX.dropbox.com", notifyX);
		ret.put("d.dropbox.com", d_dropbox);
		ret.put("api.dropbox.com", api_dropbox);
		ret.put("api-content.dropbox.com", api_content);
		ret.put("api-notify.dropbox.com", api_notify);
		
		return ret;
	}
	
	public HashMap<DNSRecord, ArrayList<SockPacket>> tagByDNS(ArrayList<SockPacket> packets, ArrayList<DNSRecord> records)
	{
		HashMap<DNSRecord, ArrayList<SockPacket>> ret = new HashMap<DNSRecord, ArrayList<SockPacket>>();
		
		for (SockPacket packet : packets)
		{
			DNSRecord lastRecord = null;
			for (DNSRecord record : records)
			{
				if (DNSRecord.belongsTo(record, packet))
				{
					lastRecord = record;
				}
			}
			
			if (lastRecord != null)
			{
				if (!ret.containsKey(lastRecord))
				{
					ArrayList<SockPacket> ps = new ArrayList<SockPacket>();
					ps.add(packet);
					ret.put(lastRecord, ps);
				}
				else
				{
					ret.get(lastRecord).add(packet);
				}
			}
			else
			{
				//not tagged
			}
		}
				
		return ret;
	}
	
	public HashMap<String, ArrayList<SockPacket>> 
	mergeDNSTag(ArrayList<SockPacket> packets, ArrayList<DNSRecord> records)
	{
		HashMap<String, ArrayList<SockPacket>> ret = new HashMap<String, ArrayList<SockPacket>>();
		
		ArrayList<SockPacket> clientX = new ArrayList<SockPacket>();
		ArrayList<SockPacket> dl_clientX = new ArrayList<SockPacket>();
		ArrayList<SockPacket> notifyX = new ArrayList<SockPacket>();
		ArrayList<SockPacket> client_lb = new ArrayList<SockPacket>();
		ArrayList<SockPacket> d_dropbox = new ArrayList<SockPacket>();
		ArrayList<SockPacket> api_dropbox = new ArrayList<SockPacket>();
		ArrayList<SockPacket> api_notify = new ArrayList<SockPacket>();
		ArrayList<SockPacket> api_content = new ArrayList<SockPacket>();
		Pattern clientP = Pattern.compile("^client\\d*\\.dropbox\\.com$");
		Pattern dl_clientP = Pattern.compile("^dl-client\\d*\\.dropbox\\.com$");
		Pattern notifyP = Pattern.compile("^notify\\d*\\.dropbox\\.com$");
		
		for (SockPacket packet : packets)
		{
			DNSRecord lastRecord = null;
			for (DNSRecord record : records)
			{
				if (DNSRecord.belongsTo(record, packet))
				{
					lastRecord = record;
				}
			}
			
			if (lastRecord != null)
			{
				if (clientP.matcher(lastRecord.name).find())
				{
					clientX.add(packet);
				}
				else if (dl_clientP.matcher(lastRecord.name).find())
				{
					dl_clientX.add(packet);
				}
				else if (notifyP.matcher(lastRecord.name).find())
				{
					notifyX.add(packet);
				}
				else if (lastRecord.name.equals("client-lb.dropbox.com"))
				{
					client_lb.add(packet);
				}
				else if (lastRecord.name.equals("d.dropbox.com"))
				{
					d_dropbox.add(packet);
				}
				else if (lastRecord.name.equals("api-content.dropbox.com"))
				{
					api_content.add(packet);
				}
				else if (lastRecord.name.equals("api.dropbox.com"))
				{
					api_dropbox.add(packet);
				}
				else if (lastRecord.name.equals("api-notify.dropbox.com"))
				{
					api_notify.add(packet);
				}
			}
		}
		ret.put("clientX.dropbox.com", clientX);
		ret.put("dl-clientX.dropbox.com", dl_clientX);
		ret.put("client-lb.dropbox.com", client_lb);
		ret.put("notifyX.dropbox.com", notifyX);
		ret.put("d.dropbox.com", d_dropbox);
		ret.put("api.dropbox.com", api_dropbox);
		ret.put("api-content.dropbox.com", api_content);
		ret.put("api-notify.dropbox.com", api_notify);
		return ret;
	}
	
	public HashMap<Connection, ArrayList<SockPacket>> tagByConn(ArrayList<SockPacket> packets, ArrayList<Connection> conns)
	{
		HashMap<Connection, ArrayList<SockPacket>> ret = new HashMap<Connection, ArrayList<SockPacket>>();
		
		for (SockPacket packet : packets)
		{
			boolean tagged = false;
			for (Connection conn : conns)
			{
				if (Connection.belongsTo(conn, packet))
				{
					tagged = true;
					if (!ret.containsKey(conn))
					{
						ArrayList<SockPacket> ps = new ArrayList<SockPacket>();
						ps.add(packet);
						ret.put(conn, ps);
					}
					else
					{
						ret.get(conn).add(packet);
					}
					break;
				}
			}
			
			if (!tagged)
			{
//				System.out.println("CONN untagged: " + packet);
			}
		}

		for (Connection conn : ret.keySet())
		{
			conn.packets = ret.get(conn);
//			conn.sortBySeq();
//			conn.reTagBySSL();
			conn.calc();
		}
		
		return ret;
	}
}
