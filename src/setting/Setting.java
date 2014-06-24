package setting;

public class Setting
{
	public static final int BUF_SIZE = 4 * 1024 * 1024;
	
	public static final int HEAD_TYPE_PCAP = 0;
	public static final int HEAD_TYPE_PACKET = 1;
	
	public static final int PCAP_HEAD_LEN = 24;
	public static final int PACKET_HEAD_LEN = 16;
	
	public static final int PCAP_MAGIC = 0xa1b2c3d4;
	public static final int PCAP_HEAD_LINKTYPE_INDEX = 20;
}
