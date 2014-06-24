package protocol;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.ArrayList;

import util.Util;

public class Connection
{
	public int srcPort, dstPort;
	public int srcIP, dstIP;
	public long start, end;
	
	public Connection(int srcPort, int dstPort, 
			int srcIP, int dstIP, 
			long start, long end)
	{
		this.srcIP = srcIP;
		this.dstIP = dstIP;
		this.srcPort = srcPort;
		this.dstPort = dstPort;
		this.start = start;
		this.end = end;
	}
	
	public ArrayList<SockPacket> packets = new ArrayList<SockPacket>();
	public int upDatalen = 0, downDatalen = 0;
	public long upSeqStart = -1, upSeqEnd = 0, downSeqStart = -1, downSeqEnd = 0;
	public double synTime = -1, firstDataTime = -1, lastDataTime = -1, finTime = -1, rstTime = -1;
	
	public void calc()
	{

		long formerUp = 0, formerDown = 0;
		for (int i = 0; i < packets.size(); i ++)
		{
			SockPacket p = packets.get(i);

			if (synTime == -1 && p.type == SockPacket.TCP_PACK_TYPE_SYN)
			{
				synTime = p.time;
			}
			if (finTime == -1 && p.type == SockPacket.TCP_PACK_TYPE_FIN)
			{
				finTime = p.time;
			}
			if (rstTime == -1 && p.type == SockPacket.TCP_PACK_TYPE_RST)
			{
				rstTime = p.time;
			}
			if (firstDataTime == -1 && p.type == SockPacket.TCP_PACK_TYPE_DATA)
			{
				firstDataTime = p.time;
			}
			if (p.type == SockPacket.TCP_PACK_TYPE_DATA 
					&& finTime == -1 && lastDataTime < p.time)
			{
				lastDataTime = p.time;
			}
			
			
			if (p.dir == SockPacket.PACKET_DIR_UP)
			{
				if (upSeqStart == -1)
				{
					upSeqStart = p.seq;
				}
				upDatalen += p.datalen;
				p.seq = p.seq - upSeqStart;
				
				if (p.seq - formerUp > SockPacket.MAX_PAYLOAD || p.seq < 0)
				{
//					System.out.println("up " + p.seq + ", " + formerUp);
					p.seq = 0;
				}
				else
				{
					formerUp = p.seq;
				}
				if (upSeqEnd < p.seq)
				{
					upSeqEnd = p.seq;
				}
			}
			else if (p.dir == SockPacket.PACKET_DIR_DOWN)
			{
				if (downSeqStart == -1)
				{
					downSeqStart = p.seq;
				}
				p.seq = p.seq - downSeqStart;
				downDatalen += p.datalen;
				
				if (p.seq - formerDown > SockPacket.MAX_PAYLOAD || p.seq < 0)
				{
//					System.out.println("down " + p.seq + ", " + formerDown);
					p.seq = 0;
				}
				else
				{
					formerDown = p.seq;
				}

				if (downSeqEnd < p.seq)
				{
					downSeqEnd = p.seq;
				}
			}
		}
	}
	
	public void print(PrintStream out, String name, double start_t, PrintStream time6out, double first_t)
	{
//		System.out.println(synTime + " " + firstDataTime + " " + lastDataTime + " " + finTime + " " + rstTime);
		out.print(name + "," + Util.ipInt2Str(srcIP) + ":" + srcPort + "," 
				+ Util.ipInt2Str(dstIP) + ":" + dstPort);
		
		boolean gap1 = (synTime != -1) && (firstDataTime != -1);
		boolean gap2 = (lastDataTime != -1) && (firstDataTime != -1);
		boolean gap3 = (finTime != -1) && (lastDataTime != -1);
		boolean gap4 = (rstTime != -1) && (finTime != -1);
		boolean gap5 = (lastDataTime != -1) && (synTime != -1);
		out.print("," + (synTime == -1 ? Float.NaN : Util.scaleTo2bit((synTime - start_t) / 1000))
				+ "," + (!gap1 ? Float.NaN : Util.scaleTo2bit((firstDataTime - synTime) / 1000)) 
				+ "," + (firstDataTime == -1 ? Float.NaN : Util.scaleTo2bit((firstDataTime - start_t) / 1000)) 
				+ "," + (!gap2 ? Float.NaN : Util.scaleTo2bit((lastDataTime - firstDataTime) / 1000)) 
				+ "," + (lastDataTime == -1 ? Float.NaN : Util.scaleTo2bit((lastDataTime - start_t) / 1000)) 
				+ "," + (!gap3 ? Float.NaN : Util.scaleTo2bit((finTime - lastDataTime) / 1000)) 
				+ "," + (finTime == -1 ? Float.NaN : Util.scaleTo2bit((finTime - start_t) / 1000)) 
				+ "," + (!gap4 ? Float.NaN : Util.scaleTo2bit((rstTime - finTime) / 1000)) 
				+ "," + (rstTime == -1 ? Float.NaN : Util.scaleTo2bit((rstTime - start_t) / 1000))
				+ "," + (!gap5 ? Float.NaN : Util.scaleTo2bit((lastDataTime - synTime) / 1000)) );
		
		boolean gap0 = (synTime != -1) && (first_t != -1);
		time6out.println((!gap0 ? Float.NaN : Util.scaleTo2bit((synTime - first_t) / 1000))
				+ "," + (!gap1 ? Float.NaN : Util.scaleTo2bit((firstDataTime - synTime) / 1000)) 
				+ "," + (!gap2 ? Float.NaN : Util.scaleTo2bit((lastDataTime - firstDataTime) / 1000)) 
				+ "," + (!gap3 ? Float.NaN : Util.scaleTo2bit((finTime - lastDataTime) / 1000)) 
				+ "," + (!gap4 ? Float.NaN : Util.scaleTo2bit((rstTime - finTime) / 1000)));
		
//		if (finTime - lastDataTime < 0)
//		{
//			System.out.println(this);
//			System.out.println(synTime + " " + firstDataTime + " " + lastDataTime + " " + finTime + " " + rstTime);
//			for (SockPacket p : packets)
//			{
//				System.out.println(p);
//			}
//			System.exit(1);
//		}
		
		out.print("," + upDatalen + "," + downDatalen);
		if (lastDataTime - synTime > 0)
		{
			out.print("," + Util.scaleTo2bit((double) upDatalen * 1000 / (lastDataTime - synTime)) 
					+ "," + Util.scaleTo2bit((double) downDatalen * 1000 / (lastDataTime - synTime)));
		}
		else
		{
			out.print(",NaN,NaN");
		}
		
		out.print("," + upSeqEnd + "," + downSeqEnd);
		if (lastDataTime - synTime > 0)
		{
			out.print("," + Util.scaleTo2bit((double) (upSeqEnd)  * 1000 / (lastDataTime - synTime)) 
					+ "," + Util.scaleTo2bit((double) (downSeqEnd)  * 1000 / (lastDataTime - synTime)));
		}
		else
		{
			out.print(",NaN,NaN");
		}
		out.println();
	}
	
	public void write(String name, double first_t)
	{
		try
		{
			String filename = "seq-time/" + name + "_" + Util.ipInt2Str(srcIP) + "_" + srcPort + "--" 
					+ Util.ipInt2Str(dstIP) + "_" + dstPort;
			
			PrintWriter pw1 = new PrintWriter(new File(filename + "_up"));
			PrintWriter pw2 = new PrintWriter(new File(filename + "_down"));
			for (SockPacket p : packets)
			{
				if (p.dir == SockPacket.PACKET_DIR_UP)
				{
					pw1.println((p.time - first_t) + "," + p.seq);
				}
				else if (p.dir == SockPacket.PACKET_DIR_DOWN)
				{
					pw2.println((p.time - first_t) + "," + p.seq);
				}
			}
			pw1.close();
			pw2.close();
		}
		catch (FileNotFoundException e)
		{
			e.printStackTrace();
		}
	}
	
	
	/**
	 * judge that whether a packet belongs to
	 * this connection, and mark its direction
	 * */
	public boolean belongsTo(SockPacket packet)
	{
		boolean ret = false;
		if (start <= packet.time && packet.time <= end)
		{
			if (packet.srcIP == srcIP
			  && packet.srcPort == srcPort
			  && packet.dstIP == dstIP
			  && packet.dstPort == dstPort)
			{
				ret = true;
				packet.dir = SockPacket.PACKET_DIR_UP;
			}
			else if (packet.srcIP == dstIP
				  && packet.srcPort == dstPort
				  && packet.dstIP == srcIP
				  && packet.dstPort == srcPort)
			{
				ret = true;
				packet.dir = SockPacket.PACKET_DIR_DOWN;
			}
		}
		
		return ret;
	}
	
	@Override
	public String toString()
	{
		return "srcIP = " + Util.ipInt2Str(srcIP)
			 + ", dstIP = " + Util.ipInt2Str(dstIP)
			 + ", src port = " + srcPort
			 + ", dst port = " + dstPort
			 + ", start = " + start
			 + ", end = " + end;
	}
	
	@Override
	public boolean equals(Object obj)
	{
		boolean ret = false;
		if (obj instanceof Connection)
		{
			ret = ((Connection) obj).srcIP == srcIP
			   && ((Connection) obj).dstIP == dstIP
			   && ((Connection) obj).srcPort == srcPort
			   && ((Connection) obj).dstPort == dstPort
			   && ((Connection) obj).start == start
			   && ((Connection) obj).end == end;
		}
		return ret;
	}
	
	@Override
	public int hashCode()
	{
		return (int) (srcIP * 1 + dstIP * 2 + srcPort * 3 + dstPort * 4 + start * 5 + end * 6);
	}
	
	public static boolean belongsTo(Connection conn, SockPacket packet)
	{
		return conn.start <= packet.time
			&& packet.time <= conn.end
			&& ((packet.srcIP == conn.srcIP
			  && packet.srcPort == conn.srcPort
			  && packet.dstIP == conn.dstIP
			  && packet.dstPort == conn.dstPort)
			 || (packet.srcIP == conn.dstIP
			  && packet.srcPort == conn.dstPort
			  && packet.dstIP == conn.srcIP
			  && packet.dstPort == conn.srcPort));
	}
}
