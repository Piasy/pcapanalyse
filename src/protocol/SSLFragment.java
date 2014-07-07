package protocol;

public class SSLFragment
{
	long seqStart, seqEnd;
	long acks, acke;
	public SSLFragment(long seqs, long seqe, long acks, long acke, double start)
	{
		seqStart = seqs;
		seqEnd = seqe;
		this.acks = acks;
		this.acke = acke;
		this.start = start;
	}
	
	
	public double start = -1, end = -1;
	
	@Override
	public String toString()
	{
		String ret = "Fragment: start = " + start + ", end = " + end
				+ ", seqs = " + seqStart + ", seqe = " + seqEnd;
		return ret;
	}
}
