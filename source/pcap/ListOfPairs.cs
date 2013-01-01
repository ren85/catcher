using System;
using System.Collections.Generic;
using System.Linq;

namespace pcap
{
	public class ListOfPairs
	{
		public List<Pair> Pairs = new List<Pair>();

		public delegate void NewRequestDelegate(Pair pair);
		public event NewRequestDelegate OnNewRequest;
		public void RaiseNewRequest(Pair pair)
		{
			if(OnNewRequest != null)
				OnNewRequest(pair);		
		}

		internal void AddRequest(Entity request)
		{
			var pair = new Pair() { Id = Pair.Counter++,  Request =  request };
			Pairs.Add(pair);	
			request.OnNewRequest += () => RaiseNewRequest(pair);
		}

		public delegate void NewResponseDelegate(Pair pair);
		public event NewResponseDelegate OnNewResponse;
		internal void RaiseNewResponse(Pair pair)
		{
			if(OnNewResponse != null)
				OnNewResponse(pair);
		}

		internal void AddResponse(Entity response, string test)
		{
			var match = Pairs.LastOrDefault(f => f.Response == null && 
				                                 f.Request.IpInfo.Dest_Ip == response.IpInfo.Source_Ip &&
				                                 f.Request.IpInfo.Dest_Port == response.IpInfo.Source_Port &&
				                                 f.Request.IpInfo.Source_Ip == response.IpInfo.Dest_Ip &&
				                                 f.Request.IpInfo.Source_Port == response.IpInfo.Dest_Port /*&& 
			                                	 f.Request._is_completed*/);
			
			if(match == null)
				return;
			match.Response = response;		
			response.OnNewResponse += () => RaiseNewResponse(match);
		}
	}
}

