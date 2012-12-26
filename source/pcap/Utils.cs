using System;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace pcap
{
	public class Utils
	{
		public static string UnGZip(byte[] byteArray)
		{
			try
			{
				using (MemoryStream inStream = new MemoryStream(byteArray))
				using (GZipStream bigStream = new GZipStream(inStream, CompressionMode.Decompress))
				using (MemoryStream bigStreamOut = new MemoryStream())
				{
						bigStream.CopyTo(bigStreamOut);
						return Encoding.UTF8.GetString(bigStreamOut.ToArray());

				}
			}
			catch (Exception)
			{
				return "Couldn't decompress.";
			}
		}
		
			
		public static string DefalteUnzip(byte[] input)
		{
			try
			{
				using (MemoryStream inputStream = new MemoryStream(input))
				using (DeflateStream gzip = new DeflateStream(inputStream, CompressionMode.Decompress))
				using (StreamReader reader = new StreamReader(gzip, System.Text.Encoding.UTF8))
				{
					return reader.ReadToEnd();
				}
			}
			catch (Exception)
			{
				return "Couldn't decompress.";
			}
		}
	}
}

