package protocol;

import java.util.Comparator;

import util.Util;

public class SockPacket
{
	public int srcPort, dstPort;
	public int srcIP, dstIP;
	public double time;
	public int length;
	public int datalen;
	public long seq, ack;
	
	public static final int MAX_PAYLOAD = 1024 * 1024;
	
	public int type;
	public static final int TCP_PACK_TYPE_RAW = 0;
	public static final int TCP_PACK_TYPE_SYN = 3;
	public static final int TCP_PACK_TYPE_ACK = 4;
	public static final int TCP_PACK_TYPE_FIN = 5;
	public static final int TCP_PACK_TYPE_DATA = 6;
	public static final int TCP_PACK_TYPE_RST = 7;
	public static final int TCP_PACK_TYPE_SSL_HANDSHAKE = 8;
	public static final int TCP_PACK_TYPE_SSL_UNKNOWN = 9;
	
	public int dir = 0;
	public static final int PACKET_DIR_UP = 1;
	public static final int PACKET_DIR_DOWN = 2;
	
	public byte[] payload;
	
	public boolean dup = false;
	public boolean ackbit = false;
	
	public SockPacket(int srcPort, int dstPort, 
			int srcIP, int dstIP, 
			double time, int length,
			int datalen, int type, long seq, long ack, boolean ackbit, byte[] payload)
	{
		this.srcIP = srcIP;
		this.dstIP = dstIP;
		this.srcPort = srcPort;
		this.dstPort = dstPort;
		this.time = time;
		this.length = length;
		this.datalen = datalen;
		this.type = type;
		this.seq = seq;
		this.ack = ack;
		this.ackbit = ackbit;
		this.payload = payload;
	}
	
	@Override
	public String toString()
	{
		String ret = "srcIP = " + Util.ipInt2Str(srcIP)
			 + ", dstIP = " + Util.ipInt2Str(dstIP)
			 + ", src port = " + srcPort
			 + ", dst port = " + dstPort
			 + ", time = " + time
			 + ", length = " + length
			 + ", datalen = " + datalen
			 + ", seq = " + seq
			 + ", ack = " + ack
			 + ", type = ";
		if (dup)
		{
			ret += "(DUP)";
		}
		switch (type)
		{
		case TCP_PACK_TYPE_RAW:
			ret += "RAW";
			break;
		case TCP_PACK_TYPE_ACK:
			ret += "ACK";
			break;
		case TCP_PACK_TYPE_SYN:
			ret += "SYN";
			break;
		case TCP_PACK_TYPE_FIN:
			ret += "FIN";
			break;
		case TCP_PACK_TYPE_DATA:
			ret += "DATA";
			break;
		case TCP_PACK_TYPE_RST:
			ret += "RST";
			break;
		case TCP_PACK_TYPE_SSL_HANDSHAKE:
			ret += "SSL_HANDSHAKE";
			break;
		default:
			ret += "UNKNOWN";
			break;
		}
		return ret;
	}
	
	public static class PackSeqComparator implements Comparator<SockPacket>
	{

		@Override
		public synchronized int compare(SockPacket o1, SockPacket o2)
		{
			if (o1.seq == o2.seq)
			{
				if (o1.time == o2.time)
				{
					return 0;
				}
				else if (o1.time < o2.time)
				{
					return -1;
				}
				else
				{
					return 1;
				}
			}
			else if (o1.seq < o2.seq)
			{
				return -1;
			}
			else
			{
				return 1;
			}
		}
	}
	
	public static class PackAckComparator implements Comparator<SockPacket>
	{

		@Override
		public synchronized int compare(SockPacket o1, SockPacket o2)
		{
			if (o1.ack == o2.ack)
			{
				if (o1.time == o2.time)
				{
					return 0;
				}
				else if (o1.time < o2.time)
				{
					return -1;
				}
				else
				{
					return 1;
				}
			}
			else if (o1.ack < o2.ack)
			{
				return -1;
			}
			else
			{
				return 1;
			}
		}
	}
}
