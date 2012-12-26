using System;
using pcap;
using System.IO;

namespace tests
{
	class MainClass
	{
		public static void Main (string[] args)
		{
			

				Capturing capture = new Capturing ();
				Tcp_packets_holder.Pairs.OnNewRequest += (pair) => 
				{

				};

				Tcp_packets_holder.Pairs.OnNewResponse += (pair) => 
				{
					var response = pair.Response;
					if(/*response.IsCompleted*/response.Headers !=  null)
					{
						WriteInfo(pair);
					}
					else
					{
						response.OnBytesAdded += () => 
						{
							if(/*response.IsCompleted*/response.Headers != null)
							{
								WriteInfo(pair);
							}
						};	
					}
				};

				capture.StartCapturing(0);
			}
			
		static void WriteInfo(Pair pair)
		{
			using (TextWriter tw  = new StreamWriter("out.txt", true)) 
			{
				tw.WriteLine("=====================================================================");
				tw.WriteLine(pair.Request.First_Line);
				tw.WriteLine(pair.Request.Headers_String+"\r\n");
				tw.WriteLine(pair.Request.Body_String);
				
				tw.WriteLine("\n");
				tw.WriteLine(pair.Response.First_Line);
				tw.WriteLine(pair.Response.Headers_String+"\r\n");
				if(pair.Response.Zipping != Zipping.None)
					tw.WriteLine(pair.Response.Unzipped_Body);
				else
					tw.WriteLine(pair.Response.Body_String);
			}
		}
		}

}
