package protocol;

import java.util.Comparator;

public class PackComparator implements Comparator<SockPacket>
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
