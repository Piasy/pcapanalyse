package util;

import java.math.BigDecimal;
import java.nio.ByteBuffer;

public class Util
{
	public static void main(String[] args)
	{
		int ip = ipStr2Int("192.168.2.103");
		System.out.println(ip);
		System.out.println(ipInt2Str(ip));
	}
	

	public static float scaleTo2bit(double value)
	{
		try
		{
			return new BigDecimal(value).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
		}
		catch (NumberFormatException e)
		{
			e.printStackTrace();
		}
		return -1.0f;
	}
	
	public static ByteBuffer bf = ByteBuffer.allocate(4);
	
	/**
	 * exit if the condition is false
	 * */
	public static void exitIfErr(boolean _assert, String msg)
	{
		if (!_assert)
		{
			System.out.println(msg);
			System.exit(1);
		}
	}
	
	public static int ipStr2Int(String ip) throws NumberFormatException
	{
		int ret = 0;
		String [] strs = ip.split("\\.");
		for (String s : strs)
		{
			ret = (ret << 8) + Integer.parseInt(s);
		}
		return ret;
	}
	
	public static String ipInt2Str(int ip) throws NumberFormatException
	{
		String ret = "";
		synchronized (bf)
		{
			bf.clear();
			bf.putInt(ip);
			for (int i = 0; i < 4; i ++)
			{
				ret += ((int) bf.get(i) + 256) % 256;
				if (i != 3)
				{
					ret += ".";
				}
			}
		}
		return ret;
	}
}
