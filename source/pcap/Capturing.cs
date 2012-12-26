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
    public partial class Capturing
    {


		ICaptureDevice device = null;
		public void StartCapturing(int device_choice)
		{			


            // Retrieve the device list
            var devices = CaptureDeviceList.Instance;

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
				device.Close();
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
                    if (tcp != null && tcp.PayloadData != null && tcp.PayloadData.Count() > 0)
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
