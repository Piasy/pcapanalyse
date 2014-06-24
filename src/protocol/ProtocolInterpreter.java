package protocol;

import java.nio.ByteBuffer;

public class ProtocolInterpreter
{
	public static final int UPPER_PROTO_TYPE_ARP = 0x0806;
	public static final int UPPER_PROTO_TYPE_IP = 0x0800;
	
	public static int getSecondProtoType(ByteBuffer bf, int length)
	{
		return 0;
	}
}
