using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Collections.Generic;

namespace pcap
{
	public class Utils
	{
		public static int MaxSizeInBytes = 5242880;
		public static string UnGZip(byte[] byteArray, Encoding Enc)
		{
			try
			{
				using (MemoryStream inStream = new MemoryStream(byteArray))
				using (GZipStream bigStream = new GZipStream(inStream, CompressionMode.Decompress))
				using (MemoryStream bigStreamOut = new MemoryStream())
				{
						bigStream.CopyTo(bigStreamOut);
						return Enc.GetString(bigStreamOut.ToArray());

				}
			}
			catch (Exception)
			{
				var s = Enc.GetString(byteArray);
				return "***Catcher: couldn't decompress***\r\n\r\n" + s;
			}
		}
		
			
		public static string DeflateUnzip(byte[] byteArray, Encoding Enc)
		{
			try
			{
				using (MemoryStream inputStream = new MemoryStream(byteArray))
				using (DeflateStream gzip = new DeflateStream(inputStream, CompressionMode.Decompress))
				using (StreamReader reader = new StreamReader(gzip, Enc))
				{
					return reader.ReadToEnd();
				}
			}
			catch (Exception)
			{
				return "***Catcher: couldn't decompress***\r\n" + Enc.GetString(byteArray);
			}
		}
	}
}

