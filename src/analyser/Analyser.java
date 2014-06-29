package analyser;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;

import protocol.Connection;
import protocol.DNSRecord;
import protocol.PacketFilter;
import protocol.PacketTagger;
import protocol.SockPacket;
import util.Util;

public class Analyser
{

	public static void main(String[] args)
	{
		File file = new File("trace.pcap");
		File connsLog = new File("connection_log.csv");
//		System.out.println(System.currentTimeMillis());
		new Analyser().analyse(file, connsLog);
	}

	/**
	 * @param file
	 * @param connsLog
	 */
	public void analyse(File file, File connsLog)
	{
		try
		{
			PrintStream out = new PrintStream(new File("out.csv"));
			
			//read connection log
			ArrayList<Connection> connections = new ArrayList<Connection>();
			BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(connsLog)));
			String line;
			while ((line = reader.readLine()) != null)
			{
				try
				{
					String [] strs = line.split(",");
					int srcIP = Util.ipStr2Int(strs[0]);
					int srcPort = Integer.parseInt(strs[1]);
					int dstIP = Util.ipStr2Int(strs[2]);
					int dstPort = Integer.parseInt(strs[3]);
					long start = Long.parseLong(strs[4]);
					long end = Long.parseLong(strs[5]);
					Connection conn = new Connection(srcPort, dstPort, srcIP, dstIP, start - 2500, end + 2500);
//					out.println(conn);
					connections.add(conn);
				}
				catch (NumberFormatException e)
				{
					e.printStackTrace();
				}
			}
			reader.close();
			
			//step 1: filt packets according to connection log
			PacketFilter filter = new PacketFilter(connections);
			ArrayList<SockPacket> packets = filter.filt(file, out);
//			double start_t = filter.getStartTime();
			double first_t = filter.getFirstTime();
			ArrayList<DNSRecord> records = filter.getDNSRecords();
			System.out.println("Step 1: filt, " + packets.size() + " packets");
			
			
//			out.println(records.size() + " dns records:\n");
//			for (DNSRecord record : records)
//			{
//				System.out.println(record);
//			}
					
			
			File seq_time = new File("seq-time");
			seq_time.mkdir();
			File dns_time = new File("dns-time");
			dns_time.mkdir();
			
			
			//step 2: tag packets by connections
			PacketTagger tagger = new PacketTagger();
			long totalUpSize = 0, totalDownSize = 0;
			HashMap<Connection, ArrayList<SockPacket>> connTaggedPackets = tagger.tagByConn(packets, connections);
			System.out.println("Step 2: tag by conns, " + connTaggedPackets.size() + " types");
			for (Connection conn : connTaggedPackets.keySet())
			{
				totalUpSize += conn.upSeqEnd;
				totalDownSize += conn.downSeqEnd;
			}
			out.println("Up good size of all conn = " + totalUpSize 
					+ ",down good size of all conn = " + totalDownSize);

			out.println("domain name,local ip:local port,remote ip:remote port,"
					+ "synTime,firstDataTime - synTime,firstDataTime,lastDataTime - firstDataTime,"
					+ "lastDataTime,finTime - lastDataTime(finish time),"
					+ "lastUpSSLTime,finTime - lastUpSSLTime,"
					+ "lastDownSSLTime,finTime - lastDownSSLTime,finTime,rstTime - finTime,rstTime,"
					+ "netTime,upDataSize,downDataSize,up throughput,down throughput,"
					+ "upGoodSize,downGoodSize,up goodput,down goodput");
			
			//step 3: tag conns by dns
			HashMap<String, ArrayList<Connection>> dnsTaggedConns = tagger.tagConnByDNS(connections, records);
			PrintStream time6out = new PrintStream(new File("data.csv"));
			//time6out.println("synTime - baseTime,firstDataTime - synTime,lastDataTime - firstDataTime,"
			//		+ "finTime - lastDataTime,rstTime - finTime");
			for (String name : dnsTaggedConns.keySet())
			{
				for (Connection conn : dnsTaggedConns.get(name))
				{
					conn.print(out, name, first_t, time6out, first_t);
					conn.write(name, first_t);
				}
			}
			
			//step 4: extract ssl fragment, done by step 2, conn.calc()
			
			//step 5: output total data goodput
			PrintStream totalGoodputout = new PrintStream(new File("totalGoodput.csv"));
			double dataStreamSyn = -1, dataStreamLastData = -1;
			long totalSize = 0;
			for (Connection conn : dnsTaggedConns.get("dl-clientX.dropbox.com"))
			{
				if (dataStreamSyn == -1)
				{
					dataStreamSyn = conn.synTime;
				}
				else if (conn.synTime != -1 && conn.synTime < dataStreamSyn)
				{
					dataStreamSyn = conn.synTime;
				}
				
				if (dataStreamLastData == -1)
				{
					dataStreamLastData = conn.lastDataTime;
				}
				else if (conn.lastDataTime != -1 && dataStreamLastData < conn.lastDataTime)
				{
					dataStreamLastData = conn.lastDataTime;
				}
				totalSize += conn.downSeqEnd + conn.upSeqEnd;
			}
			for (Connection conn : dnsTaggedConns.get("api-content.dropbox.com"))
			{
				if (dataStreamSyn == -1)
				{
					dataStreamSyn = conn.synTime;
				}
				else if (conn.synTime != -1 && conn.synTime < dataStreamSyn)
				{
					dataStreamSyn = conn.synTime;
				}
				
				if (dataStreamLastData == -1)
				{
					dataStreamLastData = conn.lastDataTime;
				}
				else if (conn.lastDataTime != -1 && dataStreamLastData < conn.lastDataTime)
				{
					dataStreamLastData = conn.lastDataTime;
				}

				totalSize += conn.downSeqEnd + conn.upSeqEnd;
			}
			if (dataStreamLastData != -1 && dataStreamSyn != -1)
			{
				totalGoodputout.println(Util.scaleTo2bit((double) totalSize / (dataStreamLastData - dataStreamSyn)));
			}
			else
			{
				totalGoodputout.println(Float.NaN);
			}
			totalGoodputout.close();
			
			//step 6: tag packets by dns
			HashMap<String, ArrayList<SockPacket>> merged = tagger.mergeDNSTag(packets, records);
			for (String key : merged.keySet())
			{
				ArrayList<SockPacket> ps = merged.get(key);
				
				PrintWriter pw1 = new PrintWriter(new File("dns-time/dns_" + key + "_conn_down"));
				PrintWriter pw12 = new PrintWriter(new File("dns-time/dns_" + key + "_conn_up"));
				for (SockPacket p : ps)
				{
					if (p.dir == SockPacket.PACKET_DIR_DOWN)
					{
						pw1.println((long) p.time + "\t" + p.seq);
					}
					else if (p.dir == SockPacket.PACKET_DIR_UP)
					{
						pw12.println((long) p.time + "\t" + p.seq);
					}
				}
				pw1.close();
				pw12.close();
			}
			
			/*HashMap<DNSRecord, ArrayList<SockPacket>> dnsTaggedPackets = tagger.tagByDNS(packets, records);
			System.out.println("Step 3: tag by dns, " + dnsTaggedPackets.size() + " types");
			for (DNSRecord record : dnsTaggedPackets.keySet())
			{
				System.out.println("\tTag " + record.name + " : " + dnsTaggedPackets.get(record).size() + " packets");
				
				ArrayList<SockPacket> ps = dnsTaggedPackets.get(record);
				String filename = "dns_" + record.name;
				PrintWriter pw1 = new PrintWriter(new File(filename + "_conn_down"));
				PrintWriter pw12 = new PrintWriter(new File(filename + "_conn_up"));
				for (SockPacket p : ps)
				{
					if (p.dir == SockPacket.PACKET_DIR_DOWN)
					{
						pw1.println((long) p.time + "\t" + p.seq);
					}
					else if (p.dir == SockPacket.PACKET_DIR_UP)
					{
						pw12.println((long) p.time + "\t" + p.seq);
					}
					
				}
				pw1.close();
				pw12.close();
				
				PrintWriter pw2 = new PrintWriter(new File(filename + "_req"));
				for (DNSRecord rec : records)
				{
					if (rec.name.equals(record.name))
					{
						pw2.println((long) rec.time / 1000);
					}
				}
				pw2.close();
			}*/
			out.close();
			time6out.close();
		}
		catch (FileNotFoundException e1)
		{
			e1.printStackTrace();
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
		
		
	}
}
