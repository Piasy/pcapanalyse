package protocol;

public class SSLFragment
{
	long seqStart, seqEnd;
	public SSLFragment(long seqs, long seqe)
	{
		seqStart = seqs;
		seqEnd = seqe;
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
