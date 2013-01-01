using System;
using System.Collections.Generic;
using System.Linq;

namespace pcap
{
	public partial class Capturing
	{
		static object api_lock = new object();
		public static List<long> ToBeRemovedIds = new List<long>();
		public static void RegisterRemovePairs(List<long> ids)
		{
			lock(api_lock)
			{
				if(ToBeRemovedIds.Count > 0)
					ToBeRemovedIds.AddRange(ids);
				else
					ToBeRemovedIds = ids;
			}
		}

		internal static void RemovePairs()
		{
			lock(api_lock)
			{
				if(ToBeRemovedIds.Count > 0)
				{
					var list =  Tcp_packets_holder.Pairs.Pairs.Where(f => ToBeRemovedIds.Contains(f.Id)).ToList();
					foreach(var pair in list)
					{
						Tcp_packets_holder.Pairs.Pairs.Remove(pair);
					}
					ToBeRemovedIds = new List<long>();
				}
			}
		}
	}
}