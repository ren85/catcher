using System;
using System.Threading;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace pcap
{
	public class Packet
	{
		public PacketDotNet.IpPacket Ip {get; set;}
		public PacketDotNet.TcpPacket Tcp {get; set;}
		
	}
	public class Tcp_packets_holder
	{
		static Thread t;
		public static void StartWorking()
		{
			t = new Thread(Tcp_packets_holder.WorkOnPackets);
			t.Start();
		}
		public static void StopWorking()
		{
			if(t != null)
				t.Abort();
		}
		public static object _lock = new object();
		public static List<Packet> Packets = new List<Packet>();
		public static List<Packet> Working_copy = new List<Packet>();
		
		public static ListOfPairs Pairs = new ListOfPairs(); 
		
		public static void WorkOnPackets()
		{				
			try
			{
				while(true)
				{
					Working_copy = new List<Packet>();
					lock(_lock)
					{
						foreach(var p in Packets)
							Working_copy.Add(p);
						Packets = new List<Packet>();
					}
					foreach(var p in Working_copy)
					{
						var req = Pairs.Pairs.LastOrDefault(f =>  f.Request.IpInfo.Dest_Ip == p.Ip.DestinationAddress.ToString() && 
								                                  f.Request.IpInfo.Dest_Port == p.Tcp.DestinationPort.ToString() &&
								                                  f.Request.IpInfo.Source_Ip == p.Ip.SourceAddress.ToString() &&
								                                  f.Request.IpInfo.Source_Port == p.Tcp.SourcePort.ToString() && 
								                                  f.Response == null);
						if(req != null)
						{
							req.Request.AddTcpPacket(p.Tcp);
							continue;
						}
						
						var res = Pairs.Pairs.LastOrDefault(f =>  f.Response != null &&
								                                  f.Response.IpInfo.Dest_Ip == p.Ip.DestinationAddress.ToString() && 
								                                  f.Response.IpInfo.Dest_Port == p.Tcp.DestinationPort.ToString() &&
								                                  f.Response.IpInfo.Source_Ip == p.Ip.SourceAddress.ToString() &&
								                                  f.Response.IpInfo.Source_Port == p.Tcp.SourcePort.ToString() && 
								                                  !f.Response._is_completed);
						if(res != null)
						{
							res.Response.AddTcpPacket(p.Tcp);
							continue;
						}
						
						var s = Encoding.UTF8.GetString(p.Tcp.PayloadData);
						if (s.StartsWith ("GET") || s.StartsWith ("POST") || 
						    s.StartsWith ("HEAD") || s.StartsWith ("PUT") || 
						    s.StartsWith ("DELETE") || s.StartsWith ("TRACE") || 
						    s.StartsWith ("OPTIONS") || s.StartsWith ("CONNECT") || 
						    s.StartsWith ("PATCH")) 
						{
							var en = new Entity()
							{
								IpInfo = new IpInfo()
								{
									Source_Ip = p.Ip.SourceAddress.ToString(),
									Source_Port = p.Tcp.SourcePort.ToString(),
									Dest_Ip = p.Ip.DestinationAddress.ToString(),
									Dest_Port = p.Tcp.DestinationPort.ToString()
								},
								IsRequest = true
							};
							Pairs.AddRequest(en);
							en.AddTcpPacket(p.Tcp);
						}
						else if (s.StartsWith ("HTTP"))
						{
							var en = new Entity()
							{
								IpInfo = new IpInfo()
								{
									Source_Ip = p.Ip.SourceAddress.ToString(),
									Source_Port = p.Tcp.SourcePort.ToString(),
									Dest_Ip = p.Ip.DestinationAddress.ToString(),
									Dest_Port = p.Tcp.DestinationPort.ToString()
								},
								IsRequest = false
							};
							Pairs.AddResponse(en);
							en.AddTcpPacket(p.Tcp);
						}
					}
					
					foreach(var r in Pairs.Pairs.Where(f => f.Request.Packets_added))
					{
						r.Request.DoWorkOnPackets();
					}
					foreach(var r in Pairs.Pairs.Where(f => f.Response != null && f.Response.Packets_added))
					{
						r.Response.DoWorkOnPackets();
					}
					Thread.Sleep(500);
				}
			}
			catch(Exception e)
			{
				Console.Error.WriteLine("Working thread: {0}", e.InnerException != null ? e.InnerException.Message+"\n"+e.InnerException.StackTrace : e.Message+"\n"+e.StackTrace);
			}
		}
	}
}

