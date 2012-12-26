using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Globalization;
using System.Threading;

namespace pcap
{


	public class Entity
	{
		public bool IsRequest { get; set; }

		public bool Packets_added { get; set; }
		List<PacketDotNet.TcpPacket> Tcp_packets = new List<PacketDotNet.TcpPacket>();

		public void AddTcpPacket (PacketDotNet.TcpPacket packet)
		{
			var p = Tcp_packets.FirstOrDefault(f => f.SequenceNumber == packet.SequenceNumber);
			if(p != null)
				Tcp_packets.Remove(p);
			Tcp_packets.Add(packet);
			Packets_added = true;
		}

		public void DoWorkOnPackets ()
		{
			bool is_new = false;
			if(Headers == null)
				is_new = true;

			Tcp_packets = Tcp_packets.OrderBy (f => f.SequenceNumber).ToList();
			List<byte> bytes = new List<byte> ();
			foreach (var p in Tcp_packets) 
			{
				bytes.AddRange (p.PayloadData);
			}

			string text = Encoding.UTF8.GetString (bytes.ToArray());
			int index = text.IndexOf ("\r\n\r\n");
			if (index == -1)
				return;

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

			First_Line = headers.Substring (0, headers.IndexOf ("\r"));
			Headers_String = headers.Substring (headers.IndexOf ("\n") + 1);
			int headers_size = System.Text.Encoding.UTF8.GetBytes (headers + "\r\n\r\n").Length;
			Body_Bytes = new List<byte> (bytes.Skip (headers_size));

			if(Packets_added)
				RaiseBytesAdded();

			if(Headers != null && IsRequest && is_new)
				RaiseNewRequest();
			if(Headers != null && !IsRequest && is_new)
				RaiseNewResponse();

			/*if(IsChunked && !_is_chunked_completed)
			{
				List<byte> completed = new List<byte>();
				WorkOnChunk(completed, Body_Bytes);
			}*/

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

				if(!IsRequest)
				{
					var length = Headers.FirstOrDefault(f => f.Item1.ToLower() == "content-length");
					if(length != null)
						Length = Convert.ToInt32(length.Item2);
					else
						Length = -1;
					
					var closed = Headers.FirstOrDefault(f => f.Item1.ToLower() == "connection");
					if(closed != null && closed.Item2.ToLower() == "close")
						IsClosed = true;
					
					var chunked = Headers.FirstOrDefault(f => f.Item1.ToLower() == "transfer-encoding");
					if(chunked != null && chunked.Item2.ToLower() == "chunked")
						IsChunked = true;
					
					var zipped = Headers.FirstOrDefault(f => f.Item1.ToLower() == "content-encoding");
					if(zipped != null && zipped.Item2.ToLower() == "gzip")
						Zipping = Zipping.Gzip;
					else if(zipped != null && zipped.Item2.ToLower() == "deflate")
						Zipping = Zipping.Deflate;
					else
						Zipping = Zipping.None;

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


		public bool _is_completed;
		public bool IsCompleted 
		{
			get
			{
				if(!_is_completed)
					_is_completed = Length == ReadSoFar || IsClosed || Status == "304" || (IsChunked && IsChunkedCompleted);

				return _is_completed;
			}
		}
		public int Length { get; set; }
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
		public bool IsChunkedCompleted 
		{
			get
			{
				if(!IsChunked)
					return false;
				
				if(_is_chunked_completed)
					return true;
				
				List<byte> completed = new List<byte>();
				return WorkOnChunk(completed, Body_Bytes);
			}
		}
		
		bool WorkOnChunk(List<byte> completed, List<byte> bb)
		{

			string body = Encoding.UTF8.GetString(bb.ToArray());
			if(!body.Contains("\n"))
				return false;
			
			var line = body.Split("\r\n".ToCharArray(), StringSplitOptions.RemoveEmptyEntries)[0];
			var s = line.Split(";".ToCharArray(), StringSplitOptions.RemoveEmptyEntries)[0];
			int size = Convert.ToInt32(s, 16);

			int l = Encoding.UTF8.GetBytes(body.Substring(0, body.IndexOf("\n")+1)).Length;
			bb = new List<byte>(bb.Skip(l));
			
			if(size == 0)
			{
				if(bb.Count() > 0)
				{
					string after_headers = Encoding.UTF8.GetString(bb.ToArray());
					if(!after_headers.EndsWith("\r\n"))
						return false;
					
					if(after_headers != "\r\n")
						Headers_String = Headers_String+"\r\n"+after_headers;
				}
				_is_chunked_completed = true;
				Body_Bytes = completed;
				return true;
			}
			else
			{
				if(bb.Count() < size+Encoding.UTF8.GetBytes("\r\n").Length)
					return false;
				completed.AddRange(bb.Take(size));
				bb = new List<byte>(bb.Skip(size+Encoding.UTF8.GetBytes("\r\n").Length));
				return WorkOnChunk(completed, bb);
			}
		}		
		
		public Zipping Zipping { get; set; }

		public string Unzipped_Body 
		{
			get
			{				
				if(Zipping == Zipping.Gzip)
				{
					return  Utils.UnGZip(Body_Bytes.ToArray());
				}
				else if(Zipping == Zipping.Deflate)
				{
					return Utils.DefalteUnzip(Body_Bytes.ToArray());
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

				_cached_string = Encoding.UTF8.GetString(Body_Bytes.ToArray());
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

