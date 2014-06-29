package protocol;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;

import setting.Setting;
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
		
	/**
	 * sort packets by seq, it should be called before calc!
	 * */
	public void sortBySeq()
	{
		for (SockPacket p : packets)
		{
			if (p.dir == SockPacket.PACKET_DIR_UP)
			{
				upPackets.add(p);
			}
			else if (p.dir == SockPacket.PACKET_DIR_DOWN)
			{
				downPackets.add(p);
			}
		}

		PackComparator comparator = new PackComparator();
		Collections.sort(upPackets, comparator);
		Collections.sort(downPackets, comparator);
		
		//to relative seq
		if (upPackets.size() != 0)
		{
			long upSeqStart = upPackets.get(0).seq;
			for (SockPacket p : upPackets)
			{
				p.seq = p.seq - upSeqStart;
			}
		}
		if (downPackets.size() != 0)
		{
			long downSeqStart = downPackets.get(0).seq;
			for (SockPacket p : downPackets)
			{
				p.seq = p.seq - downSeqStart;
			}
		}
	}
	
	protected boolean overlaped(SockPacket pf, SockPacket pa)
	{
//		System.out.println(pf.seq + " " + pa.seq + " " + (pf.seq + pf.datalen));
		return (pf.seq <= pa.seq) && (pa.seq < pf.seq + pf.datalen);
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
	
	ArrayList<SSLFragment> upFragments = new ArrayList<SSLFragment>();
	ArrayList<SSLFragment> downFragments = new ArrayList<SSLFragment>();

	int xxxx = 1;
	public void reTagBySSL()
	{
		if (srcPort != 443 && dstPort != 443)
		{
			return;
		}
		reTagOneDir(upPackets, upFragments);
		reTagOneDir(downPackets, downFragments);
		
		for (SockPacket p : upPackets)
		{
			System.out.println(xxxx + " : " + p);
			xxxx ++;
		}
		for (SockPacket p : downPackets)
		{
			System.out.println(xxxx + " : " + p);
			xxxx ++;
		}

//		for (SSLFragment f : upFragments)
//		{
//			f.calc();
//			System.out.println(f);
////			System.out.println("up Fregment " + xxxx);
////			xxxx ++;
//		}
////		xxxx = 1;
//		for (SSLFragment f : downFragments)
//		{
//			f.calc();
//			System.out.println(f);
////			System.out.println("down Fregment " + xxxx);
////			for (SockPacket p : f.packets)
////			{
////				System.out.println("\t\t" + p);
////			}
////			xxxx ++;
//		}
////		System.out.println("==============================");
	}
	
	protected void reTagOneDir(ArrayList<SockPacket> packets, ArrayList<SSLFragment> fragments)
	{
		int i = 1;
		ByteBuffer bf = ByteBuffer.allocate(Setting.BUF_SIZE);
		
		if (packets.size() > 1)
		{
			bf.clear();
			bf.put(packets.get(i).payload);
			int index = 0;	//pointer to fragment start
			int len = 0;
			boolean littleLeft = false;
			int left = 0;
			while (i < packets.size())
			{
				int lastUniqueIndex = lastUniqueIndex(packets, i);
				if (overlaped(packets.get(lastUniqueIndex), packets.get(i)))
				{
					packets.get(i).dup = true;
					packets.get(i).type = packets.get(i - 1).type;
//					System.out.println("dup! " + i);
					
					i ++;
					if (i < packets.size())
					{
						bf.clear();
						bf.put(packets.get(i).payload);
						index = 0;
						len = 0;
					}
					continue;
				}
				
//				System.out.println(i + " : org = " + packets.get(i).type);
				if ((packets.get(i).type == SockPacket.TCP_PACK_TYPE_DATA
				  || packets.get(i).type == SockPacket.TCP_PACK_TYPE_SSL_HANDSHAKE)
						&& !overlaped(packets.get(lastUniqueIndex), packets.get(i)))
				{
					int contentType = ((int) bf.get(index) + 256) % 256;
//					System.out.println(i + " : cur = " + contentType + ", index = " + index);
					if (contentType == PacketFilter.SSL_CIPHER_SPEC 
					 || contentType == PacketFilter.SSL_HANDSHAKE)
					{
//						System.out.println(i + " : HANDSHAKE");
						packets.get(i).type = SockPacket.TCP_PACK_TYPE_SSL_HANDSHAKE;
						i ++;
						if (i < packets.size())
						{
							bf.clear();
							bf.put(packets.get(i).payload);
							index = 0;
							len = 0;
						}
					}
					else if (contentType == PacketFilter.SSL_CONTENT_APPDATA)
					{
//						System.out.println(i + " : DATA");
						packets.get(i).type = SockPacket.TCP_PACK_TYPE_DATA;
						
						if (littleLeft)
						{
							littleLeft = false;
							len = ((int) bf.getShort(index + 3) + 65536) % 65536 + 5 - left;
						}
						else
						{
							len += ((int) bf.getShort(index + 3) + 65536) % 65536 + 5;	//including ssl header
						}
						
//						System.out.println("len = " + len + ", index = " + index);
						ArrayList<SockPacket> fragPackets = new ArrayList<SockPacket>();
						fragPackets.add(packets.get(i));
						if (len == packets.get(i).payload.length)
						{
							fragments.add(new SSLFragment(fragPackets));
							i ++;
							if (i < packets.size())
							{
								bf.clear();
								bf.put(packets.get(i).payload);
								index = 0;
								len = 0;
							}
						}
						else
						{
							boolean restart = false;
							while (i < packets.size() && len != packets.get(i).payload.length)
							{
								if (packets.get(i).payload.length < len)
								{
									len -= packets.get(i).payload.length;
									
									i ++;
									while (i < packets.size() && overlaped(packets.get(lastUniqueIndex), packets.get(i)))
									{//re-transmitted packets
										fragPackets.add(packets.get(i));
//										System.out.println(i + " : dup DATA");
										packets.get(i).type = SockPacket.TCP_PACK_TYPE_DATA;
										i ++;
									}
									
									if (i < packets.size())
									{
//										System.out.println(i + " : continue");
//										System.out.println(i + " : DATA");
										packets.get(i).type = SockPacket.TCP_PACK_TYPE_DATA;
										fragPackets.add(packets.get(i));
									}
								}
								else if (packets.get(i).payload.length > len)
								{
									fragments.add(new SSLFragment(fragPackets));
									
									if (packets.get(i).payload.length >= len + 5)
									{
//										System.out.println(i + " : restart");
										bf.clear();
										bf.put(packets.get(i).payload);
										fragPackets = new ArrayList<SockPacket>();
										fragPackets.add(packets.get(i));
									}
									else
									{
//										System.out.println(i + " : restart, but left little");
										littleLeft = true;
										left = packets.get(i).payload.length - len;
//										System.out.println("left = " + left);
										bf.clear();	//!clear former payload
										bf.put(packets.get(i).payload);	//!and re-put current payload
										fragPackets = new ArrayList<SockPacket>();
										fragPackets.add(packets.get(i));
										i ++;
										bf.put(packets.get(i).payload);	//!and next payload
										fragPackets.add(packets.get(i));
									}
									index = len;
									restart = true;
									break;
								}
							}
							
							if (!restart)
							{
//								System.out.println(i + " : finish");
								fragments.add(new SSLFragment(fragPackets));
								i ++;
								if (i < packets.size())
								{
//									System.out.println("before clear, type = " + (((int) bf.get(0) + 256) % 256));
									bf.clear();
									bf.put(packets.get(i).payload);
//									int ttt = (((int) bf.get(0) + 256) % 256);
//									System.out.println("after clear, type = " + ttt);
									index = 0;
									len = 0;
								}
							}
						}
					}
					else
					{
//						System.out.println(i + " : UNKNOWN");
						packets.get(i).type = SockPacket.TCP_PACK_TYPE_SSL_UNKNOWN;
						i ++;
						if (i < packets.size())
						{
							bf.clear();
							bf.put(packets.get(i).payload);
							index = 0;
							len = 0;
						}
					}
				}
				else
				{
					i ++;
					if (i < packets.size())
					{
						bf.clear();
						bf.put(packets.get(i).payload);
						index = 0;
						len = 0;
					}
				}
			}
		}
	}

	ArrayList<SockPacket> upPackets = new ArrayList<SockPacket>();
	ArrayList<SockPacket> downPackets = new ArrayList<SockPacket>();
	ArrayList<SockPacket> upPackStream = new ArrayList<SockPacket>();
	ArrayList<SockPacket> downPackStream = new ArrayList<SockPacket>();
	public void calc()
	{
		norm();
		rebuildPackSeq(upPackets, downPackets, upPackStream);
		rebuildPackSeq(downPackets, upPackets, downPackStream);
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
	protected void rebuildPackSeq(ArrayList<SockPacket> ups, ArrayList<SockPacket> downs, ArrayList<SockPacket> stream)
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
		
//		for (SockPacket p : packs)
//		{
//			System.out.println(p);
//		}
		
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

//		for (SockPacket p : acks)
//		{
//			System.out.println(p);
//		}
		
		int ai = acks.size() - 1, pi = packs.size() - 1;
		System.out.println("ai = " + ai + ", pi = " + pi);
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
			
//			System.out.println("stride: " + ai + ", " + pi + ", " + matched(acks.get(ai), packs.get(pi)));
			int hi = pi;
			contributeTo(tmp, packs.get(hi));
			//tmp.add(packs.get(hi));
			pi --;
			//while (pi >= 0 && continuous(packs.get(hi), packs.get(pi)))
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
//				ai --;
				while (ai >= 0 && matched(acks.get(ai), packs.get(pi)) >= 0)
				{
					ai --;
				}
				if (ai < 0)
				{
					break;
				}
				//ai: the first ack after pi
				
//				hi = pi;
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
//		System.out.println("stride: " + ai + ", " + pi);
		for (int j = tmp.size() - 1; j >= 0; j --)
		{
			stream.add(tmp.get(j));
		}
		
		
		/*for (int i = packs.size() - 1; i >= 0; i --)
		{
			if (acks.size() != 0 && matched(acks.get(acks.size() - 1), packs.get(i)))
			{
				ArrayList<SockPacket> tmp = new ArrayList<SockPacket>();
				int hi = i;
				tmp.add(packs.get(hi));
				for (int j = i - 1; j >= 0; j --)
				{
					if (continuous(packs.get(hi), packs.get(j)))
					{
						tmp.add(packs.get(j));
						hi = j;
					}
				}
				
				for (int j = tmp.size() - 1; j >= 0; j --)
				{
					stream.add(tmp.get(j));
				}
				
				break;
			}
		}*/
		
		/*int lastP = 0, curP = -1;
		for (SockPacket ack : acks)
		{
			boolean found = false;
			for (int i = curP + 1; i < packs.size(); i ++)
			{
				if (matched(ack, packs.get(i)))
				{
					lastP = curP;
					curP = i;
					found = true;
					break;
				}
			}
			
			if (!found)
			{
				System.out.println("Error, ack doesn't match any packet!");
				System.out.println(ack);
			}
			else
			{
				if (curP - lastP == 1)
				{
					stream.add(packs.get(curP));
				}
				else
				{
					ArrayList<SockPacket> tmp = new ArrayList<SockPacket>();
					int hi = curP;
					tmp.add(packs.get(hi));
					for (int i = curP - 1; i > lastP; i --)
					{
						//! not only continuous with the packet behind,
						//but also the last packet in stream
						if (continuous(packs.get(hi), packs.get(i)))
						{
							tmp.add(packs.get(i));
							hi = i;
						}
					}
					
					int index;
					for (index = tmp.size() - 1; index >= 0; index --)
					{
						if (stream.size() == 0 
						 || continuous(tmp.get(index), stream.get(stream.size() - 1)))
						{
							break;
						}
					}
					for (int i = index; i >= 0; i --)
					{
						stream.add(tmp.get(index));
					}
				}
			}
		}*/
		
		for (int i = 1; i < stream.size(); i ++)
		{
			if (!continuous(stream.get(i), stream.get(i - 1)))
			{
				System.out.println("un-continuous!: ");
				System.out.println(stream.get(i - 1));
				System.out.println(stream.get(i) + "\n");
			}
//			System.out.println(stream.get(i));
		}
		System.out.println("==============================");
	}
	
	protected int matched(SockPacket ack, SockPacket pack)
	{
//		System.out.println("ack : " + ack);
//		System.out.println("pack : " + pack);
//		System.out.println(ack.ack + " " + (pack.seq + pack.datalen));
		
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
	
	protected boolean continuous(SockPacket pa, SockPacket pf)
	{
		return pa.seq == pf.seq + pf.datalen;
	}
	
	protected void contributeTo(ArrayList<SockPacket> arr, SockPacket p)
	{
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
	
	public void calc2()
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
