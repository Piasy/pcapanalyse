package protocol;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;

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
	public long upSeqEnd = 0, downSeqEnd = 0;
	public double synTime = -1, firstDataTime = -1, lastDataTime = -1, finTime = -1, rstTime = -1;
	public double lastUpSSLTime = -1, lastDownSSLTime = -1;
	
	ArrayList<SockPacket> upPackets = new ArrayList<SockPacket>();
	ArrayList<SockPacket> downPackets = new ArrayList<SockPacket>();
	ArrayList<SSLFragment> upFragments = new ArrayList<SSLFragment>();
	ArrayList<SSLFragment> downFragments = new ArrayList<SSLFragment>();
	public void calc()
	{
		norm();
		calc2();
				
		if (srcPort == 443 || dstPort == 443)
		{			
			ArrayList<SockPacket> downAcks = extractAcks(upPackets);	//ack for down stream, in up stream
			ArrayList<SockPacket> upAcks = extractAcks(downPackets);	//ack for up stream, in down stream
//			System.out.println("acks : " + upAcks.size() + ", " + downAcks.size());
//			for (SockPacket pp : downAcks)
//			{
//				System.out.println(pp);
//			}
//			System.out.println("---------------------------------");

			Collections.sort(upPackets, new SockPacket.PackSeqComparator());
			Collections.sort(downPackets, new SockPacket.PackSeqComparator());

//			System.out.println(this);
			if (upPackets.size() > 0)
			{
				SockPacket pu = upPackets.get(upPackets.size() - 1);
				if (pu.seq + pu.datalen > 0)
				{
					ByteBuffer upPayload = ByteBuffer.allocate((int) (pu.seq + pu.datalen));
					int uplen = extractPayload(upPackets, upPayload);
					extractSSLFrag(upPayload, uplen, upFragments);
					calcFragTime(upFragments, upAcks);
					if (upFragments.size() > 0)
					{
						//lastUpSSLTime = upFragments.get(upFragments.size() - 1).end;
						for (int i = upFragments.size() - 1; i >= 0; i --)
						{
							if (upFragments.get(i).end != -1)
							{
//								System.out.println(upFragments.get(i));
								lastUpSSLTime = upFragments.get(i).end;
								break;
							}
						}
					}
					
//					System.out.println("uplen = " + uplen + ", " + upPackets.size() + ", " + (pu.seq + pu.datalen));
//					for (int i = 0; i < uplen; i ++)
//					{
//						System.out.print(upPayload.get(i) + " ");
//						if (i > 700)
//						{
//							break;
//						}
//					}
//					System.out.println("============================");
				}
			}
			
			if (downPackets.size() > 0)
			{
				SockPacket pd = downPackets.get(downPackets.size() - 1);
				if (pd.seq + pd.datalen > 0)
				{
					ByteBuffer downPayload = ByteBuffer.allocate((int) (pd.seq + pd.datalen));
					int downlen = extractPayload(downPackets, downPayload);
					extractSSLFrag(downPayload, downlen, downFragments);
					calcFragTime(downFragments, downAcks);
					if (downFragments.size() > 0)
					{
						//lastDownSSLTime = downFragments.get(downFragments.size() - 1).end;
						for (int i = downFragments.size() - 1; i >= 0; i --)
						{
//							System.out.println(downFragments.get(i));
							if (downFragments.get(i).end != -1)
							{
//								System.out.println(downFragments.get(i));
								lastDownSSLTime = downFragments.get(i).end;
								break;
							}
						}
					}
//					System.out.println("downlen = " + downlen + ", " + upPackets.size() + ", " + (pd.seq + pd.datalen));
				}
			}
		}
		
//		System.out.println(upFragments.size() + " " + downFragments.size());
//		System.out.println(lastUpSSLTime + " " + lastDownSSLTime + " " + finTime);
//		System.out.println("========================================");
	}
	
	protected ArrayList<SockPacket> extractAcks(ArrayList<SockPacket> packs)
	{
		ArrayList<SockPacket> acks = new ArrayList<SockPacket>();
		ArrayList<SockPacket> tmpAcks = new ArrayList<SockPacket>();
		for (SockPacket p : packs)
		{
			if (p.ackbit)
			{
				tmpAcks.add(p);
			}
		}
		Collections.sort(tmpAcks, new SockPacket.PackAckComparator());
		for (SockPacket p : tmpAcks)
		{
			if ((acks.size() == 0 || acks.get(acks.size() - 1).ack != p.ack) 
					&& (finTime == -1 || p.time < finTime))
			{
				acks.add(p);
			}
		}
		return acks;
	}
	
	protected int extractPayload(ArrayList<SockPacket> stream, ByteBuffer bf)
	{		
		int index = 0;
		while (index < stream.size())
		{
			if (stream.get(index).seq == 1 
				&& stream.get(index).datalen > 0)
			{
				break;
			}
			index ++;
		}
		
		int pos = 1;
		if (index < stream.size())
		{
			bf.put(stream.get(index).payload);
			pos += stream.get(index).payload.length;
			index ++;
			
			while (index < stream.size())
			{
				if (stream.get(index).datalen > 0)
				{
					int offset = (int) (pos - stream.get(index).seq);
					int len = stream.get(index).datalen;
					if (0 <= offset && offset < len)
					{
						bf.put(stream.get(index).payload, offset, len - offset);
						pos += (len - offset);
					}
					else if (len <= offset)
					{
						//do nothing
					}
					else
					{
						System.out.println("Broken seq!");
//						for (int i = index - 3; i <= index + 3; i ++)
//						{
//							if (0 <= i && i < stream.size())
//							{
//								System.out
//										.println(stream.get(i));
//							}
//						}
//						System.out.println("=====================================");
						break;
					}
				}
				index ++;
			}
		}
		
		return pos;
	}
	
	protected void extractSSLFrag(ByteBuffer payload, int len, ArrayList<SSLFragment> fragments)
	{
		int pos = 0;
		while (pos + 5 < len)
		{
			int contType = ((int) payload.get(pos) + 256) % 256;
			int version = ((int) payload.getShort(pos + 1) + 65536) % 65536;
			int datalen = ((int) payload.getShort(pos + 3) + 65536) % 65536;
			if (version == PacketFilter.SSL_VERSION)
			{
				if (contType == PacketFilter.SSL_CONTENT_APPDATA)
				{
					fragments.add(new SSLFragment(pos + 1, pos + datalen + 6));
				}
				pos += (datalen + 5);
			}
			else
			{
				System.out.println("Broken payload!");
				break;
			}
		}
	}
	

	
	protected void calcFragTime(ArrayList<SSLFragment> fragments, ArrayList<SockPacket> acks)
	{
		for (SSLFragment f : fragments)
		{
			f.end = getAckTime(f.seqEnd, acks);
		}
	}
	
	protected double getAckTime(long seq, ArrayList<SockPacket> acks)
	{
		double time = -1;
		for (SockPacket ack : acks)
		{
			if (matched(ack, seq) >= 0)
			{
				time = ack.time;
				break;
			}
		}
		
		return time;
	}
	
	protected int lastUniqueIndex(ArrayList<SockPacket> packets, int start)
	{
		for (int i = start - 1; i >= 0; i --)
		{
			if (!packets.get(i).dup)
			{
				return i;
			}
		}
		
		//this exit point shouldn't be reached
		return start - 1;
	}
	
	public long upSeqStart = -1, upAckStart = -1, downSeqStart = -1, downAckStart = -1;
	protected void norm()
	{
		long formerUp = 0, formerDown = 0;
		for (int i = 0; i < packets.size(); i ++)
		{
			SockPacket p = packets.get(i);
			if (p.dir == SockPacket.PACKET_DIR_UP)
			{
				if (upSeqStart == -1)
				{
					upSeqStart = p.seq;
				}
				p.seq -= upSeqStart;
				if (p.ackbit && upAckStart == -1)
				{
					upAckStart = p.ack;
				}
				p.ack -= (upAckStart - 1);
				
				if (p.seq - formerUp > SockPacket.MAX_PAYLOAD || p.seq < 0)	//bad packet
				{
					p.seq = 0;
					p.ackbit = false;
				}
				else
				{
					formerUp = p.seq;
					upPackets.add(p);
				}
			}
			else if (p.dir == SockPacket.PACKET_DIR_DOWN)
			{
				if (downSeqStart == -1)
				{
					downSeqStart = p.seq;
				}
				p.seq = p.seq - downSeqStart;
				if (p.ackbit && downAckStart == -1)
				{
					downAckStart = p.ack;
				}
				p.ack -= (downAckStart - 1);
				
				if (p.seq - formerDown > SockPacket.MAX_PAYLOAD || p.seq < 0)
				{
					p.seq = 0;
					p.ackbit = false;
				}
				else
				{
					formerDown = p.seq;
					downPackets.add(p);
				}
			}
		}
	}
	
	/**
	 * data: up => down
	 * */
	protected ArrayList<SockPacket> rebuildPackSeq(ArrayList<SockPacket> ups, 
			ArrayList<SockPacket> downs, ArrayList<SockPacket> stream)
	{
		ArrayList<SockPacket> packs = new ArrayList<SockPacket>();
		ArrayList<SockPacket> acks = new ArrayList<SockPacket>();
		for (SockPacket p : ups)
		{
			if (p.type != SockPacket.TCP_PACK_TYPE_ACK)
			{
				packs.add(p);
			}
		}
		Collections.sort(packs, new SockPacket.PackSeqComparator());
		
		ArrayList<SockPacket> tmpAcks = new ArrayList<SockPacket>();
		for (SockPacket p : downs)
		{
			if (p.ackbit)
			{
				tmpAcks.add(p);
			}
		}
		Collections.sort(tmpAcks, new SockPacket.PackAckComparator());
		
		for (SockPacket p : tmpAcks)
		{
			if (acks.size() == 0 || acks.get(acks.size() - 1).ack != p.ack)
			{
				acks.add(p);
			}
		}
		
		int ai = acks.size() - 1, pi = packs.size() - 1;
//		System.out.println("ai, pi = " + ai + ", " + pi);
		ArrayList<SockPacket> tmp = new ArrayList<SockPacket>();
		ArrayList<SockPacket> tmp2 = new ArrayList<SockPacket>();
		long MAX_LEN = 65536;
		while (ai >= 0)
		{
			while (pi >= 0 && matched(acks.get(ai), packs.get(pi)) != 0)
			{
				pi --;
			}
			if (pi < 0)
			{
				break;
			}
			
			int hi = pi;
			contributeTo(tmp, packs.get(hi));
			//tmp.add(packs.get(hi));
			pi --;
			int pos = pi;
			while (pos >= 0 && packs.get(hi).seq - packs.get(pos).seq < MAX_LEN)
			{
				if (continuous(packs.get(hi), packs.get(pos)))
				{
					hi = pos;
					contributeTo(tmp, packs.get(hi));
					//tmp.add(packs.get(hi));
				}
				pos --;
			}
			pi = hi;
			
			//pi: last continuous packet
			if (pi > 0)
			{
				while (ai >= 0 && matched(acks.get(ai), packs.get(pi)) >= 0)
				{
					ai --;
				}
				if (ai < 0)
				{
					break;
				}
				//ai: the first ack after pi
				
				while (pi >= 0 && matched(acks.get(ai), packs.get(pi)) != 0)
				{
					pi --;
				}
				if (pi < 0)
				{
					break;
				}
				
				int lo = pi;
				tmp2.clear();
				//tmp2.add(packs.get(lo));	//! pi > 0, so pi will be added at next iteration
				//for (int i = pi + 1; i <= hi; i ++)	//hi is the last continuous, so it has been added!
				for (int i = pi + 1; i < hi; i ++)
				{
					if (continuous(packs.get(i), packs.get(lo)))
					{
						lo = i;
						tmp2.add(packs.get(lo));
					}
				}
				for (int i = tmp2.size() - 1; i >= 0; i --)
				{
					//contributeTo(tmp, packs.get(i));	//!stupid!
					contributeTo(tmp, tmp2.get(i));
					//tmp.add(tmp2.get(i));
				}
			}
			else
			{
				break;
			}
		}

		for (int j = tmp.size() - 1; j >= 0; j --)
		{
			stream.add(tmp.get(j));
		}
		
//		for (int i = 1; i < stream.size(); i ++)
//		{
//			if (!continuous(stream.get(i), stream.get(i - 1)))
//			{
//				System.out.println("un-continuous!: ");
//				System.out.println(stream.get(i - 1));
//				System.out.println(stream.get(i) + "\n");
//			}
////			System.out.println(stream.get(i));
//		}
//		System.out.println("==============================");
		
		return acks;
	}
	
	protected int matched(SockPacket ack, SockPacket pack)
	{
//		System.out.println("ack : " + ack);
//		System.out.println("pack : " + pack);
		if (pack.type == SockPacket.TCP_PACK_TYPE_SYN)
		{
			if (ack.ack == pack.seq + 1)
			{
				return 0;
			}
			else if (ack.ack > pack.seq + 1)
			{
				return 1;
			}
			else
			{
				return -1;
			}
		}
		else if (ack.type == SockPacket.TCP_PACK_TYPE_FIN)
		{
			if (ack.ack == pack.seq + pack.datalen || ack.ack == pack.seq + pack.datalen + 1)
			{
				return 0;
			}
			else if (ack.ack > pack.seq + pack.datalen + 1)
			{
				return 1;
			}
			else
			{
				return -1;
			}
		}
		else
		{
			if (ack.ack == pack.seq + pack.datalen)
			{
				return 0;
			}
			else if (ack.ack > pack.seq + pack.datalen)
			{
				return 1;
			}
			else
			{
				return -1;
			}
		}
	}
	
	protected int matched(SockPacket ack, long seqe)
	{
//		System.out.println("match : " + seqe + " => " + ack);
		if (ack.ack == seqe)
		{
			return 0;
		}
		else if (ack.ack > seqe)
		{
			return 1;
		}
		else
		{
			return -1;
		}
	}
	
	protected boolean continuous(SockPacket pa, SockPacket pf)
	{
		return pa.seq == pf.seq + pf.datalen;
	}
	
	protected void contributeTo(ArrayList<SockPacket> arr, SockPacket p)
	{
//		System.out.println(p);
		boolean exist = false;
		for (SockPacket pp : arr)
		{
			if (pp.time == p.time)
			{
				exist = true;
				break;
			}
		}
		if (!exist)
		{
			arr.add(p);
		}
		else
		{
			System.out.println("exist!: " + p);
		}
	}
	
	protected void calc2()
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
				//p.seq = p.seq - upSeqStart;

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
				//p.seq = p.seq - downSeqStart;
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
		//System.out.println(synTime + " " + firstDataTime + " " + lastDataTime + " " + finTime + " " + rstTime);
		out.print(name + "," + Util.ipInt2Str(srcIP) + ":" + srcPort + "," 
				+ Util.ipInt2Str(dstIP) + ":" + dstPort);
		
		boolean gap1 = (synTime != -1) && (firstDataTime != -1);
		boolean gap2 = (lastDataTime != -1) && (firstDataTime != -1);
		boolean gap3 = (finTime != -1) && (lastDataTime != -1);
		boolean gap4 = (rstTime != -1) && (finTime != -1);
		boolean gap5 = (lastDataTime != -1) && (synTime != -1);
		
		boolean gap7 = (finTime != -1) && (lastUpSSLTime != -1);
		boolean gap8 = (finTime != -1) && (lastDownSSLTime != -1);
		
		out.print("," + (synTime == -1 ? Float.NaN : Util.scaleTo2bit((synTime - start_t) / 1000))
				+ "," + (!gap1 ? Float.NaN : Util.scaleTo2bit((firstDataTime - synTime) / 1000)) 
				+ "," + (firstDataTime == -1 ? Float.NaN : Util.scaleTo2bit((firstDataTime - start_t) / 1000)) 
				+ "," + (!gap2 ? Float.NaN : Util.scaleTo2bit((lastDataTime - firstDataTime) / 1000)) 
				+ "," + (lastDataTime == -1 ? Float.NaN : Util.scaleTo2bit((lastDataTime - start_t) / 1000)) 
				+ "," + (!gap3 ? Float.NaN : Util.scaleTo2bit((finTime - lastDataTime) / 1000)) 
				+ "," + (lastUpSSLTime == -1 ? Float.NaN : Util.scaleTo2bit((lastUpSSLTime - start_t) / 1000)) 
				+ "," + (!gap7 ? Float.NaN : Util.scaleTo2bit((finTime - lastUpSSLTime) / 1000)) 
				+ "," + (lastDownSSLTime == -1 ? Float.NaN : Util.scaleTo2bit((lastDownSSLTime - start_t) / 1000)) 
				+ "," + (!gap8 ? Float.NaN : Util.scaleTo2bit((finTime - lastDownSSLTime) / 1000)) 
				+ "," + (finTime == -1 ? Float.NaN : Util.scaleTo2bit((finTime - start_t) / 1000)) 
				+ "," + (!gap4 ? Float.NaN : Util.scaleTo2bit((rstTime - finTime) / 1000)) 
				+ "," + (rstTime == -1 ? Float.NaN : Util.scaleTo2bit((rstTime - start_t) / 1000))
				+ "," + (!gap5 ? Float.NaN : Util.scaleTo2bit((lastDataTime - synTime) / 1000)) );
		
		boolean gap0 = (synTime != -1) && (first_t != -1);
		time6out.println((!gap0 ? Float.NaN : Util.scaleTo2bit((synTime - first_t) / 1000))
				+ "," + (!gap1 ? Float.NaN : Util.scaleTo2bit((firstDataTime - synTime) / 1000)) 
				+ "," + (!gap2 ? Float.NaN : Util.scaleTo2bit((lastDataTime - firstDataTime) / 1000)) 
				+ "," + (!gap3 ? Float.NaN : Util.scaleTo2bit((finTime - lastDataTime) / 1000)) 
				+ "," + (!gap7 ? Float.NaN : Util.scaleTo2bit((finTime - lastUpSSLTime) / 1000)) 
				+ "," + (!gap8 ? Float.NaN : Util.scaleTo2bit((finTime - lastDownSSLTime) / 1000)) 
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
