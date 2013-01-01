using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Globalization;
using System.Threading;

namespace pcap
{

	public class TcpPacketWrapper
	{
		public PacketDotNet.TcpPacket Packet {get; set;}
		public long Counter { get; set; } 
	}
	public class Entity
	{
		public long Next_sequence_number { get; set; }

		public bool IsRequest { get; set; }

		public bool Packets_added { get; set; }
		List<TcpPacketWrapper> Tcp_packets = new List<TcpPacketWrapper>();
		long counter = 0;
		public void AddTcpPacket (PacketDotNet.TcpPacket packet)
		{
			Next_sequence_number = packet.SequenceNumber+packet.PayloadData.Length;
			Tcp_packets.Add(new TcpPacketWrapper(){ Packet = packet, Counter = counter++});
			Packets_added = true;
		}

		//this is not incremental, i.e. same work must be redone every time (every 0.5 sec) while request/response is not finished
		public void DoWorkOnPackets ()
		{
			if(IsChunked && _is_chunked_failed)
			{
				Packets_added = false;
				return;
			}

			Tcp_packets = Tcp_packets.OrderBy (f => f.Packet.SequenceNumber).ThenBy(f => f.Counter).ToList();
			List<byte> bytes = new List<byte> ();
			for(int i=0; i<Tcp_packets.Count(); i++)
			{
				if( i != Tcp_packets.Count()-1 && Tcp_packets[i+1].Packet.SequenceNumber == Tcp_packets[i].Packet.SequenceNumber)
					continue;
				
				bytes.AddRange (Tcp_packets[i].Packet.PayloadData);
			}

			bool is_new = false;

			if(Headers == null)
				is_new = true;

			string text = Encoding.UTF8.GetString (bytes.ToArray());
			int index = text.IndexOf ("\r\n\r\n");
			if (index == -1)
				return;

			Headers_Completed = true;

			string headers = text.Substring (0, index);
			if (headers.StartsWith ("GET") || headers.StartsWith ("POST") || 
				headers.StartsWith ("HEAD") || headers.StartsWith ("PUT") || 
				headers.StartsWith ("DELETE") || headers.StartsWith ("TRACE") || 
				headers.StartsWith ("OPTIONS") || headers.StartsWith ("CONNECT") || 
				headers.StartsWith ("PATCH")) 
			{
				IsRequest = true;
			} 
			else 
			{
				IsRequest = false;
			}

			if(headers.IndexOf ("\r") != -1)
			{
				First_Line = headers.Substring (0, headers.IndexOf ("\r"));			

				Headers_String = headers.Substring (headers.IndexOf ("\n") + 1);
				int headers_size = System.Text.Encoding.UTF8.GetBytes (headers + "\r\n\r\n").Length;
				Body_Bytes = new List<byte> (bytes.Skip (headers_size));

				if(Length > Utils.MaxSizeInBytes)
					Body_Bytes = new List<byte>(Enc.GetBytes("***Catcher: body with size greater than 5 Mb is not captured***"));

				if(IsChunked && !_is_chunked_completed)
				{
					WorkOnChunk(Body_Bytes.ToArray());
				}
			}

			if(Headers != null && IsRequest && is_new)
				RaiseNewRequest();
			if(Headers != null && !IsRequest && is_new)
				RaiseNewResponse();

			if(Packets_added)
				RaiseBytesAdded();

			Packets_added = false;
		}
		public delegate void BytesAddedDelegate();
		public event BytesAddedDelegate OnBytesAdded;
		public void RaiseBytesAdded()
		{
			if(OnBytesAdded != null)
				OnBytesAdded();
		}

		public delegate void NewRequestDelegate();
		public event NewRequestDelegate OnNewRequest;
		public void RaiseNewRequest()
		{
			if( OnNewRequest != null)
				OnNewRequest();
		}

		public delegate void NewResponseDelegate();
		public event NewResponseDelegate OnNewResponse;
		public void RaiseNewResponse()
		{
			if(OnNewResponse != null)
				OnNewResponse();
		}

		public string First_Line { get; set; }
		public List<Tuple<string, string>> Headers
		{
			get;
			set;
		}
		public bool Headers_Completed { get; set; }
		string _headers_string;
		public string Headers_String 
		{
			get 
			{
				return _headers_string;
			}
			set
			{
				_headers_string = value;
				Headers = new List<Tuple<string, string>>();
				if(string.IsNullOrEmpty(value))
					return;

				string[] parts = value.Split("\n".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);
				foreach(var p in parts)
				{
					string[] h = p.Split(":".ToCharArray(), StringSplitOptions.None);
					if(h.Count() > 1)
						Headers.Add(new Tuple<string, string>(h[0].TrimNullable(), h[1].TrimNullable()));
				}


				var length = Headers.FirstOrDefault(f => f.Item1.ToLower() == "content-length");
				if(length != null)
				{
					Length = Convert.ToInt32(length.Item2);
				}
				else
				{
					Length = -1;
				}
				
				var closed = Headers.FirstOrDefault(f => f.Item1.ToLower() == "connection");
				if(closed != null && closed.Item2.ToLower() == "close")
					IsClosed = true;
				
				var chunked = Headers.FirstOrDefault(f => f.Item1.ToLower() == "transfer-encoding");
				if(chunked != null && chunked.Item2.ToLower() == "chunked")
					IsChunked = true;

				if(!IsRequest)
				{
					var zipped = Headers.FirstOrDefault(f => f.Item1.ToLower() == "content-encoding");
					if(zipped != null && zipped.Item2.ToLower() == "gzip")
						Zipping = Zipping.Gzip;
					else if(zipped != null && zipped.Item2.ToLower() == "deflate")
						Zipping = Zipping.Deflate;
					else
						Zipping = Zipping.None;

					if(Length > Utils.MaxSizeInBytes)
						Zipping = pcap.Zipping.None;

					Status = First_Line.Split(null)[1];
				}
			}
		}


		public List<byte> Body_Bytes { get; set; }
		public IpInfo IpInfo { get; set; }
		public string Host 
		{
			get
			{
				var host = Headers.FirstOrDefault(f => f.Item1.ToLower() == "host");
				if(host == null)
					return null;
				else
					return host.Item2;
			}
		}
		public string Protocol 
		{ 
			get
			{
				return "http";
			}
		}
		public string Url
		{
			get
			{
				List<string> parts = First_Line.Split(" ".ToCharArray(), StringSplitOptions.RemoveEmptyEntries)
											   .Select(f => f.ToLower())
											   .Where(f => !string.IsNullOrEmpty(f))
											   .ToList<string>();
				if(parts.Count() > 1)
					return parts[1];
				else
					return null;
			}
		}


		/*public bool IsRequestOver
		{
			get
			{
				return IsRequest && First_Line != null && First_Line.StartsWith("GET") && Headers_Completed;
			}
		}
		public bool _is_completed
		{
			get
			{
				return Length == ReadSoFar || IsClosed || Status == "304" || (IsChunked && _is_chunked_completed) || IsRequestOver;
			}
		}
		public bool IsCompleted 
		{
			get
			{
				return Length == ReadSoFar || IsClosed || Status == "304" || (IsChunked && IsChunkedCompleted) || IsRequestOver;
			}
		}*/
		public int Length = -1;
		public int ReadSoFar 
		{
			get
			{
				if(Body_Bytes == null)
					return 0;
				else
					return Body_Bytes.Count;
			}
		}
		public string Status { get; set; }		
		public bool IsClosed { get; set; }
		public bool IsChunked { get; set; }
		bool _is_chunked_completed;
		bool _is_chunked_failed { get; set; }
		/*public bool IsChunkedCompleted 
		{
			get
			{
				if(!IsChunked)
					return false;
				
				if(_is_chunked_completed)
					return true;

				return WorkOnChunk(Body_Bytes.ToArray());
			}
		}*/
		
		void WorkOnChunk(byte[] bb)
		{
			try
			{
				int iter_counter = 0;
				int max_iter_counter = 2500;
				int max_size_in_bytes = 1638400;
				if(bb.Length > max_size_in_bytes)
					throw new Exception("Body too large to dechunk.");

				if(_is_chunked_completed)
					return;

				if(_is_chunked_failed)
					return;

				byte[] nlb = Enc.GetBytes("\r\n");
				string body = Enc.GetString(bb.ToArray());
				if(!body.Contains("\r\n0\r\n"))
					return;

				var line = new String(body.Take(body.IndexOf("\r\n")).ToArray());
				var s = line.Split(";".ToCharArray(), StringSplitOptions.RemoveEmptyEntries)[0];
				int size = Convert.ToInt32(s.Trim(), 16);

				int skip = Enc.GetBytes(line).Length+nlb.Length;
				byte[] tmp = new byte[bb.Length-skip];
				for(int j=skip; j<bb.Length; j++)
					tmp[j-skip] = bb[j];
				bb = tmp;

				List<byte> completed = new List<byte>();
				while(true)
				{
					if(size == 0)
					{
						if(bb.Length > 0)
						{
							string after_headers = Enc.GetString(bb);
							if(!after_headers.EndsWith("\r\n"))
								return;
							
							if(after_headers != "\r\n")
								Headers_String = Headers_String+"\r\n"+after_headers;
						}
						_is_chunked_completed = true;
						Body_Bytes = completed;
						return;
					}
					for(int j=0; j<size; j++)
						completed.Add(bb[j]);

					int length = bb.Length;
					tmp = new byte[length-size-nlb.Length];
					for(int j=size+nlb.Length; j<length; j++)
						tmp[j-size-nlb.Length] = bb[j];
					bb = tmp;
					int i;
					List<char> hex_digits = new List<char>() {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'a', 'B', 'b', 'C', 'c', 'D', 'd', 'E', 'e', 'F', 'f'};
					for(i=0; i<bb.Length-1; i++)
					{
						iter_counter++;
						if(i > 30 || iter_counter > max_iter_counter)
						{
							throw new Exception("Coudn't dechunk in time");
						}

						if(bb[i] == nlb[1])
						{
							//try
							//{
							tmp = new byte[i];
							for(int j=0; j<i; j++)
								tmp[j] = bb[j];
							string number = Enc.GetString(tmp).Trim();
							number = new String(number.ToArray<char>().Where(f => hex_digits.Contains(f)).ToArray<char>());
							size = Convert.ToInt32(number, 16);
							//}
							//catch(Exception )
							//{
							//	Console.WriteLine(Enc.GetString (completed.ToArray()));
							//}
							tmp = new byte[bb.Length-i-1];
							for(int j=i+1; j<bb.Length; j++)
								tmp[j-i-1] = bb[j];
							bb = tmp;
							i=0;
							break;
						}
					}
					if(i != 0)
						return;
				}
			}
			catch(Exception)
			{
				_is_chunked_failed = true;
				var b = Enc.GetBytes("***Catcher: couldn't combine chunks***\r\n\r\n");
				int l = b.Length;
				byte[] res = new byte[b.Length+bb.Length];
				for(int j=0; j<b.Length; j++)
					res[j] = b[j];
				for(int j=0; j<bb.Length; j++)
					res[l+j] = bb[j];
				Body_Bytes = new List<byte>(res);
				return;
			}
		}		

		public Encoding Enc
		{
			get
			{	
				try
				{
					var h = Headers.FirstOrDefault(f => f.Item1.ToLower().Trim() == "content-type");
					if(h == null || !h.Item2.Contains("charset"))
						return Encoding.UTF8;
					var p = h.Item2.Split(";".ToCharArray());
					var charset = p.FirstOrDefault(f => f.Contains("charset")).Split("=".ToCharArray())[1].Trim().ToLower();
					return Encoding.GetEncoding(charset);
				}
				catch(Exception)
				{
					return Encoding.UTF8;
				}
			}
		}
		public Zipping Zipping { get; set; }

		public string Unzipped_Body 
		{
			get
			{				
				if(Zipping == Zipping.Gzip)
				{
					return  Utils.UnGZip(Body_Bytes.ToArray(), Enc);
				}
				else if(Zipping == Zipping.Deflate)
				{
					return Utils.DeflateUnzip(Body_Bytes.ToArray(), Enc);
				}
				else
				{
					return Body_String;
				}
			}
		}

		int _last_length;
		string _cached_string;
		public string Body_String 
		{
			get
			{
				if(_last_length == Body_Bytes.Count())
					return _cached_string;

				_cached_string = Enc.GetString(Body_Bytes.ToArray());
				_last_length = Body_Bytes.Count();
				return _cached_string;
			}
		}
	}	
	public class IpInfo
	{
		public string Source_Ip { get; set; }
		public string Source_Port { get; set; }
		public string Dest_Ip { get; set; }
		public string Dest_Port { get; set; }
	}
	public class Pair
	{
		internal static long Counter { get; set; }
		public long Id { get; set; }
		public Entity Request { get; set; }
		public Entity Response { get; set; }
	}
	public static class Ext
	{
		public static string TrimNullable(this string value)
		{
			if(string.IsNullOrEmpty(value))
				return value;
			
			return value.Trim();			
		}			
	}
	public enum Zipping
	{
		Gzip,
		Deflate,
		None
	}
}

