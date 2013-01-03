using System;
using System.Net.NetworkInformation;
using System.Collections.Generic;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Text;
using System.Linq;
using System.Threading;


namespace pcap
{
	public class DeviceInfo
	{
		public string Name { get; set; }
		public int Number { get; set; }
	}
    public partial class Capturing
    {


		ICaptureDevice device = null;
		CaptureDeviceList devices { get; set; }
		public Capturing()
		{
			// Retrieve the device list
			devices = CaptureDeviceList.Instance;
		}
		public List<DeviceInfo> GetDevices()
		{
			List<DeviceInfo> res = new List<DeviceInfo>();
			int counter = 0;
			foreach(var d in devices)
			{
				res.Add(new DeviceInfo() { Name = d.Name + (string.IsNullOrEmpty(d.Description) ? "" : " ("+d.Description+")"), Number = counter});
				counter++;
			}
			return res;
		}
		public void StartCapturing(int device_choice)
		{
            // If no devices were found print an error
            if(devices.Count < 1)
            {
                throw new Exception("No devices were found on this machine");
            }


			device = devices[device_choice];

            //Register our handler function to the 'packet arrival' event
            device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            device.Open();

            // Start capture 'INFINTE' number of packets
            device.Capture();
        }
		public void StopCapturing ()
		{
			if(device != null)
			{
				device.StopCapture();
				device.Close();
				device = null;
			}
		}

		public string GetStatistics()
		{
			if(device == null)
				return "";

			return string.Format("Received packets: {0}, dropped packets: {1}, interface dropped packets: {2}", device.Statistics.ReceivedPackets, device.Statistics.DroppedPackets, device.Statistics.InterfaceDroppedPackets);
		}
        
		private static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            if(packet is PacketDotNet.EthernetPacket)
            {
                var ip = PacketDotNet.IpPacket.GetEncapsulated(packet);
                if(ip != null)
				{
                    var tcp = PacketDotNet.TcpPacket.GetEncapsulated(packet);
                    if (tcp != null && tcp.PayloadData != null && tcp.PayloadData.Length > 0)
                    {
						lock(Tcp_packets_holder._lock)
						{
							Tcp_packets_holder.Packets.Add(new Packet() { Ip = ip, Tcp = tcp });
						}
					}
                }
            }
        }

	}
}
