package protocol;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.util.ArrayList;

import setting.Setting;
import util.Util;

public class PacketFilter
{
	public static final int LIBPCAP_LINKTYPE_ETHERNET = 1;
	public static final int LIBPCAP_LINKTYPE_LINUX_SLL = 113;
	public static final int LINUX_SLL_OFFSET = 2;
	
	public static final short SECOND_PROTO_TYPE_ARP = 0x0806;
	public static final short SECOND_PROTO_TYPE_IP = 0x0800;
	
	public static final byte THIRD_PROTO_TYPE_TCP = 0x06;
	public static final byte THIRD_PROTO_TYPE_UDP = 0x11;
	
	public static final int SECOND_PROTO_TYPE_INDEX = 12;
	public static final int THIRD_PROTO_TYPE_INDEX = 23;
	
	public static final int IP_VER_IHL_INDEX = 14;
	public static final int IP_SRC_ADDR_INDEX = 26;
	public static final int IP_DST_ADDR_INDEX = 30;
	
	public static final int SOCKET_SRC_PORT_INDEX = 34;
	public static final int SOCKET_DST_PORT_INDEX = 36;
	public static final int TCP_SEQ_INDEX = 38;
	public static final int TCP_HEAD_AND_FLAG_INDEX = 46;
	
	public static final int SSL_HANDSHAKE = 22;
	public static final int SSL_CIPHER_SPEC = 20;
	public static final int SSL_CONTENT_APPDATA = 23;
	
	public static final int TCP_HEAD_START_INDEX = 34;
	
	public static final int DNS_Q_COUNT_INDEX = 46;
	public static final int DNS_AR_COUNT_INDEX = 48;
	public static final int DNS_FIRST_NAME_LABEL_INDEX = 54;
	
	public static final int SOCKET_PORT_DNS = 53;
	
	ArrayList<Connection> connections = new ArrayList<Connection>();
	ArrayList<DNSRecord> records = new ArrayList<DNSRecord>();
	double start_t = -1, first_t = -1;
	
	public PacketFilter(ArrayList<Connection> conns)
	{
		connections = conns;
	}
	
	
	int count = 0;
	/**
	 * filt packets according to connection log
	 * */
	public ArrayList<SockPacket> filt(File file, PrintStream out)
	{
		ArrayList<SockPacket> ret = new ArrayList<SockPacket>();
		try
		{
			byte [] buf = new byte[Setting.BUF_SIZE];
			ByteBuffer bf = ByteBuffer.allocate(Setting.BUF_SIZE);
			RandomAccessFile rfin = new RandomAccessFile(file, "r");
			
			int read;
			
			//read global header
			read = rfin.read(buf, 0, Setting.PCAP_HEAD_LEN);
			Util.exitIfErr(read == Setting.PCAP_HEAD_LEN, "pcap head len error!");
			
			bf.clear();
			bf.put(buf, 0, read);
			boolean inversed = (bf.getInt(0) != Setting.PCAP_MAGIC);
//			System.out.println("inversed = " + inversed);
			
			putHeader(bf, buf, 0, read, inversed, Setting.HEAD_TYPE_PCAP);
			int linkType = bf.getInt(Setting.PCAP_HEAD_LINKTYPE_INDEX);
//			System.out.println("Link type = " + linkType);
			
			while ((read = rfin.read(buf, 0, Setting.PACKET_HEAD_LEN)) != -1)
			{
				Util.exitIfErr(read == Setting.PACKET_HEAD_LEN, "packet head len error!");
				
				putHeader(bf, buf, 0, read, inversed, Setting.HEAD_TYPE_PACKET);
				
				int tv_sec = bf.getInt(0), tv_usec = bf.getInt(4);
				int caplen = bf.getInt(8), len = bf.getInt(12);
				double time = ((double) tv_sec) * 1000 + ((double) tv_usec) / 1000;
//				System.out.println("tv_sec = " + tv_sec + ", tv_usec = " + tv_usec
//						+ ", caplen = " + caplen + ", len = " + len);
				
				if (first_t == -1)
				{
					first_t = time;
				}
				
				read = rfin.read(buf, 0, caplen);
//				Util.exitIfErr(read == caplen, "read packet error!");
				if (read != caplen)
				{
					System.out.println("read packet error!");
					break;
				}
				if (caplen != len)
				{
					System.out.println("capture data not enough!");
					break;
				}
				bf.clear();
				bf.put(buf, 0, read);
				
				switch (linkType)
				{
				case LIBPCAP_LINKTYPE_ETHERNET:
				{
					SockPacket packet = filt(bf, len, time, 0);
					if (packet != null)
					{
						ret.add(packet);
					}
					break;
				}
				case LIBPCAP_LINKTYPE_LINUX_SLL:
				{
					SockPacket packet = filt(bf, len, time, LINUX_SLL_OFFSET);
					if (packet != null)
					{
						ret.add(packet);
					}
					break;
				}
				default:
					break;
				}
				
				count ++;
//				System.out.println("packet " + count);
//				if (count == 200)
//				{
//					System.exit(1);
//				}
			}
			
			rfin.close();
		}
		catch (FileNotFoundException e)
		{
			e.printStackTrace();
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
		System.out.println(count + " packets");
		return ret;
	}
	
	/**
	 * get dns records, must be called after
	 * filt()
	 * */
	public ArrayList<DNSRecord> getDNSRecords()
	{
		return records;
	}
	
	/**
	 * get time of the first packet that belongs to dropbox
	 * */
	public double getStartTime()
	{
		return start_t;
	}

	/**
	 * get time of the first packet in this capture
	 * */
	public double getFirstTime()
	{
		return first_t;
	}
	
	/**
	 * put bytes into bytebuffer, according to the byte order,
	 * and this method will clear the bf
	 * */
	protected void putHeader(ByteBuffer bf, byte [] buf, int offset, int length, boolean inversed, int type)
	{
		bf.clear();
		switch (type)
		{
		case Setting.HEAD_TYPE_PCAP:
			Util.exitIfErr(length == Setting.PCAP_HEAD_LEN, "pcap head len error in putHedder!");
			if (inversed)
			{
				//other field
				for (int i = offset; i < offset + length - 8; i ++)
				{
					bf.put(buf[i]);
				}
				
				//snaplen field
				for (int i = offset + length - 5; i >= offset + length - 8; i --)
				{
					bf.put(buf[i]);
				}
				
				//linktype field
				for (int i = offset + length - 1; i >= offset + length - 4; i --)
				{
					bf.put(buf[i]);
				}
			}
			else
			{
				bf.put(buf, offset, length);
			}
			break;
		case Setting.HEAD_TYPE_PACKET:
			if (inversed)
			{
				//tv_sec field
				for (int i = offset + 3; i >= offset; i --)
				{
					bf.put(buf[i]);
				}
				
				//tv_usec field
				for (int i = offset + 7; i >= offset + 4; i --)
				{
					bf.put(buf[i]);
				}
				
				//caplen field
				for (int i = offset + 11; i >= offset + 8; i --)
				{
					bf.put(buf[i]);
				}
				
				//len field
				for (int i = offset + 15; i >= offset + 12; i --)
				{
					bf.put(buf[i]);
				}
			}
			else
			{
				bf.put(buf, offset, length);
			}
			break;
		default:
			break;
		}
	}
	
	ByteBuffer seqBf = ByteBuffer.allocate(8);
	/**
	 * decide a whether a packet belongs to one connection
	 * of this program, according to the connection log
	 * */
	protected SockPacket filt(ByteBuffer bf, int len, double time, int linkHeadOff)
	{
		SockPacket ret = null;
				
		//decode protocol stack
		short secondType = bf.getShort(SECOND_PROTO_TYPE_INDEX + linkHeadOff);
		if (secondType == SECOND_PROTO_TYPE_IP)
		{
//			System.out.println("IP packet");
			int srcIP = bf.getInt(IP_SRC_ADDR_INDEX + linkHeadOff);
			int dstIP = bf.getInt(IP_DST_ADDR_INDEX + linkHeadOff);
			int ipheadlen = (bf.get(IP_VER_IHL_INDEX + linkHeadOff) & 0x0f) * 4;
			byte thirdType = bf.get(THIRD_PROTO_TYPE_INDEX + linkHeadOff);
			
//			System.out.println("src = " + Util.ipInt2Str(srcIP) + ", dst = " + Util.ipInt2Str(dstIP) 
//					+ ", headlen = " + headlen + ", proto = " + thirdType);
			
			switch (thirdType)
			{
			case THIRD_PROTO_TYPE_TCP:
//				System.out.println("TCP packet");
				if (ipheadlen == 20)
				{
					int srcPort = ((int) bf.getShort(SOCKET_SRC_PORT_INDEX + linkHeadOff) + 65536) % 65536;
					int dstPort = ((int) bf.getShort(SOCKET_DST_PORT_INDEX + linkHeadOff) + 65536) % 65536;
//					System.out.println("src port = " + srcPort + ", dst port = " + dstPort);
					int headAndFlag = ((int) bf.getShort(TCP_HEAD_AND_FLAG_INDEX + linkHeadOff) + 65536) % 65536;
					int tcpheadlen = (headAndFlag & 0x0000f000) >> 10;
					int datalen = len - IP_VER_IHL_INDEX - ipheadlen - tcpheadlen;
					seqBf.clear();
					seqBf.putInt(0);
					seqBf.putInt(bf.getInt(TCP_SEQ_INDEX + linkHeadOff));
					long seq = seqBf.getLong(0);
					
					int packType = 0;
					if ((headAndFlag & 0x00000002) != 0)
					{
						packType = SockPacket.TCP_PACK_TYPE_SYN;
					}
					else if ((headAndFlag & 0x00000001) != 0)
					{
						packType = SockPacket.TCP_PACK_TYPE_FIN;
					}
					else if ((headAndFlag & 0x00000004) != 0)
					{
						packType = SockPacket.TCP_PACK_TYPE_RST;
					}
					else if (0 < datalen)
					{
						if (srcPort == 443 || dstPort == 443)
						{
							int contentType = ((int) bf.get(TCP_HEAD_START_INDEX + tcpheadlen + linkHeadOff) + 256) % 256;
							if (contentType == SSL_CONTENT_APPDATA)
							{
								packType = SockPacket.TCP_PACK_TYPE_DATA;
							}
							else
							{
								packType = SockPacket.TCP_PACK_TYPE_SSL_HANDSHAKE;
							}
						}
						else
						{
							packType = SockPacket.TCP_PACK_TYPE_DATA;
						}
					}
					else if (0 == datalen)
					{
						packType = SockPacket.TCP_PACK_TYPE_ACK;
					}
					
					byte[] payload = new byte[datalen];
					System.arraycopy(bf.array(), len - datalen, payload, 0, datalen);
					SockPacket packet = new SockPacket(srcPort, dstPort, srcIP, dstIP, 
							time, len, datalen, packType, seq, payload);
					
//					if (Util.ipInt2Str(dstIP).equals("107.22.197.31") && srcPort == 6899)
//					System.out.println(packet);
					
					for (Connection conn : connections)
					{
						if (conn.belongsTo(packet))
						{
//							System.out.println("yes");
							ret = packet;
							if (start_t == -1)
							{
								start_t = time;
							}
							else if (time < start_t)
							{
								start_t = time;
							}
							break;
						}
					}
				}
				break;
			case THIRD_PROTO_TYPE_UDP:
//				System.out.println("UDP packet");
				if (ipheadlen == 20)
				{
					int srcPort = ((int) bf.getShort(SOCKET_SRC_PORT_INDEX + linkHeadOff) + 65536) % 65536;
					int dstPort = ((int) bf.getShort(SOCKET_DST_PORT_INDEX + linkHeadOff) + 65536) % 65536;
					
					if (srcPort == SOCKET_PORT_DNS || dstPort == SOCKET_PORT_DNS)
					{
//						System.out.println("DNS packet");
						int qCount = ((int) bf.getShort(DNS_Q_COUNT_INDEX + linkHeadOff) + 65536) % 65536;
						int arCount = ((int) bf.getShort(DNS_AR_COUNT_INDEX + linkHeadOff) + 65536) % 65536;
						
						DNSRecord record = decodeDNSPacket(bf, qCount, arCount, linkHeadOff);
						if (record != null)
						{
//							System.out.println(record);
							record.time = time;
							records.add(record);
						}
					}
				}
				break;

			default:
//				System.out.println("ohter third layer packet");
				break;
			}
		}
		else
		{
//			System.out.println("ohter second layer packet");
		}
		
		return ret;
	}
	
	protected DNSRecord decodeDNSPacket(ByteBuffer bf, int qCount, int arCount, int linkHeadOff)
	{
		DNSRecord ret = null;
		if (qCount != 1)
		{
			System.out.println("too many questions");
			return ret;
		}
		
		if (arCount != 0)
		{
			ret = new DNSRecord();
			ret.middle = new ArrayList<String>();
		}
		
		int index = DNS_FIRST_NAME_LABEL_INDEX + linkHeadOff;
		for (int i = 0; i < qCount; i ++)
		{
			int nameIndex = index;
			String dn = "";
			int label = ((int) bf.get(nameIndex) + 256) % 256;
			nameIndex ++;
			while (label != 0)
			{
				if (label < 0xc0)
				{
					for (int j = 0; j < label; j ++)
					{
						char ch = ((char) ((int) (bf.get(nameIndex) + 256) % 256));
						dn += ch;
						nameIndex ++;
					}
					label = ((int) bf.get(nameIndex) + 256) % 256;
					nameIndex ++;
					if (label != 0)
					{
						dn += ".";
					}
				}
				else
				{
					int offset = (((int) bf.getShort(nameIndex - 1) + 65536) % 65536) & 0x3fff;
					nameIndex = DNS_FIRST_NAME_LABEL_INDEX + linkHeadOff - 12 + offset;
					label = ((int) bf.get(nameIndex) + 256) % 256;
					nameIndex ++;
				}
			}
			if (index < nameIndex)
			{
				index = nameIndex;
			}
			else
			{
				index += 2;
			}
//			int _type = ((int) bf.getShort(index) + 65536) % 65536;
			index += 2;
//			int _class = ((int) bf.getShort(index) + 65536) % 65536;
			index += 2;
//			System.out.println("dns query: name = " + dn + ", type = " + _type + ", class = " + _class);
			if (ret != null)
			{
				ret.name = dn;
			}
		}
		
		for (int i = 0; i < arCount; i ++)
		{
			int nameIndex = index;
			String dn = "";
			int label = ((int) bf.get(nameIndex) + 256) % 256;
			nameIndex ++;
			while (label != 0)
			{
				if (label < 0xc0)
				{
					for (int j = 0; j < label; j ++)
					{
						char ch = ((char) ((int) (bf.get(nameIndex) + 256) % 256));
						dn += ch;
						nameIndex ++;
					}
					label = ((int) bf.get(nameIndex) + 256) % 256;
					nameIndex ++;
					if (label != 0)
					{
						dn += ".";
					}
				}
				else
				{
					int offset = (((int) bf.getShort(nameIndex - 1) + 65536) % 65536) & 0x3fff;
					nameIndex = DNS_FIRST_NAME_LABEL_INDEX + linkHeadOff - 12 + offset;
					label = ((int) bf.get(nameIndex) + 256) % 256;
					nameIndex ++;
				}
			}
			if (index < nameIndex)
			{
				index = nameIndex;
			}
			else
			{
				index += 2;
			}
			int _type = ((int) bf.getShort(index) + 65536) % 65536;
			index += 2;
//			int _class = ((int) bf.getShort(index) + 65536) % 65536;
			index += 2;
//			int _ttl = bf.getInt(index);
			index += 4;
			int _datalen = ((int) bf.getShort(index) + 65536) % 65536;
			index += 2;

//			System.out.println("dns answer: name = " + dn + ", type = " + _type + ", class = " + _class
//					+ ", ttl = " + _ttl + ", datalen = " + _datalen);

			if (ret != null && i != 0)
			{
				ret.middle.add(dn);
			}
			
			if (_type == 1)
			{
				Util.exitIfErr(_datalen == 4, "dns packet ans format error!");
				int _ip = bf.getInt(index);
				index += 4;
//				System.out.println(", ip = " + Util.ipInt2Str(_ip));
				
				if (ret != null)
				{
//					ret.ip = _ip;
					ret.ips.add(_ip);
				}
			}
			else
			{
				//skip middle result
				index += _datalen;
			}
		}
		
		return ret;
	}
}
