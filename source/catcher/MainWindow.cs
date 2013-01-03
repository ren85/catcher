using System;
using Gtk;
using System.Collections;
using catcher;
using pcap;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using Pango;
using System.IO;

class ItemModel
{
	public string Number { get; set; }
	/*public string Status { get; set; }*/
	public string Protocol { get; set; }
	public string Host { get; set; }
	public string Url { get; set; }

	public Pair Pair { get; set; }
	public string RequestText { get; set; }
	public string ResponseText { get; set; }
	public List<byte> RequestBody { get; set; }
	public List<byte> ResponseBody { get; set; } 
}

class ItemsView : MyListView<ItemModel>
{
	public ItemsView () : base("#", /*"Status",*/ "Protocol", "Host", "Url")
	{
	}
	
	protected override void RenderCell (CellRendererText render, int index, ItemModel item)
	{
		if(item == null)
			return;
		switch (index)
		{
			case 0:
				render.Text = item.Number;
				break;
			/*case 1:
				render.Text = item.Status;
				break;*/
			case 1:
				render.Text = item.Protocol;
				break;
			case 2:
				render.Text = item.Host;
				break;
			case 3:
				render.Text = item.Url;
				break;

		}
	}
}

public partial class MainWindow: Gtk.Window
{	


	ItemsView view { get; set; }
	static object _lock = new object();
	int undisplayed_counter = 0;
	List<ItemModel> items = new List<ItemModel>();
	Capturing capture;
	int counter = 0;
	Thread t;
	public MainWindow (): base ("catcher")
	{
		Build();
		view = new ItemsView();
		view.Reorderable = true;
		view.Selection.Mode = SelectionMode.Multiple;

		view.KeyPressEvent += (object o, KeyPressEventArgs args) => 
		{
			if (args.Event.Key == Gdk.Key.Delete)
			{
				var s_items = view.SelectedItems.ToList<ItemModel>();
				List<long> ids = new List<long>();
				if(s_items.Count > 0)
				{
					textview1.Buffer.Text = "";
					textview2.Buffer.Text = "";

					lock(_lock)
					{
						selection_on = false;
						foreach(ItemModel i in s_items)
						{
							view.RemoveItem(i);
							items.Remove(i);
							ids.Add(i.Pair.Id);
						}
						Capturing.RegisterRemovePairs(ids);
						selection_on = true;
					}
				}
			}
		};

		foreach(var column in view.Columns)
			column.Reorderable = true;
		listview1.Child = view;
		listview1.ShowAll();
		view.ModifyFont(FontDescription.FromString("serif 9"));
		//view.ModifyBase(StateType.Normal, new Gdk.Color(150,205,205));
		//view.ModifyText(StateType.Normal, new Gdk.Color(230,232,250));
		textview1.ModifyFont(FontDescription.FromString("monospace bold 10"));
		textview2.ModifyFont(FontDescription.FromString("monospace bold 10"));
		textview1.ModifyBase(StateType.Normal, new Gdk.Color(82,82,82));
		textview1.ModifyText(StateType.Normal, new Gdk.Color(217,135,25));
		textview2.ModifyBase(StateType.Normal, new Gdk.Color(82,82,82));
		textview2.ModifyText(StateType.Normal, new Gdk.Color(217,135,25));

		view.ItemSelected += (ItemModel[] items) => 
		{
			if(selection_on)
			{
				lock(_lock)
				{
					if(items.Count() > 0)
					{
						if(!string.IsNullOrEmpty(items[0].RequestText))
							textview1.Buffer.Text = items[0].RequestText;
						else
							textview1.Buffer.Text = "";
						if(!string.IsNullOrEmpty(items[0].ResponseText))
							textview2.Buffer.Text = items[0].ResponseText;
						else
							textview2.Buffer.Text = "";
					}
					else
					{
						textview1.Buffer.Text = "";
						textview2.Buffer.Text = "";
					}
					SelectedItem = items[0];
				}
			}
			else
			{
				SelectedItem = null;
			}
		};

		Tcp_packets_holder.StartWorking();
		StartCapturing();
	}

	bool selection_on = true;
	ItemModel SelectedItem
	{
		get;
		set;
	}
	System.Timers.Timer timer {get; set;}
	void StartCapturing()
	{
		int saved = GetSavedDevice();
		capture = new Capturing ();
		var menu_item = new MenuItem("Devices");
		menubar1.Insert(menu_item, 1);
		var submenu = new Menu();
		menu_item.Submenu = submenu;
		List<Tuple<MenuItem, DeviceInfo>> map = new List<Tuple<MenuItem, DeviceInfo>>();
		foreach(var d in capture.GetDevices())
		{
			MenuItem md = new MenuItem(d.Name);
			if(d.Number == saved)
				statusbar1.Push(0, "Sniffing on: " + d.Name);
			map.Add(new Tuple<MenuItem, DeviceInfo>(md, d));
			md.Activated += (sender, e) => 
			{
				var di = map.Single(f => f.Item1 == sender as MenuItem).Item2;
				statusbar1.Push(0, "Sniffing on: " + di.Name);
				t.Abort();
				t = new Thread(f => StartCapturingOnANewThread(di.Number));
				t.Start();
				SaveDevice(di.Number);
			};
			submenu.Append(md);
		}
		menu_item.ShowAll();
		Tcp_packets_holder.Pairs.OnNewRequest += (pair) =>
		{
			var request = pair.Request;
			ItemModel item = new ItemModel()
			{
				Pair = pair,
				Number = counter++.ToString(),
				Host = request.Host,
				Protocol = request.Protocol,
				Url = request.Url,
				RequestText = request.First_Line+ "\n" + request.Headers_String+"\n\n"+request.Body_String
			};

			request.OnBytesAdded += () => 
			{
				lock(_lock)
				{
					item.RequestText = request.First_Line+ "\n" + request.Headers_String+"\n\n"+request.Body_String;
				}
			};	
			lock(_lock)
			{
				items.Add(item);
				undisplayed_counter++;
			}
		};
		
		Tcp_packets_holder.Pairs.OnNewResponse += (pair) => 
		{
			var response = pair.Response;
			if(response.First_Line != null)
			{
				OnResponseReady(pair);
			}

			response.OnBytesAdded += () => 
			{
				if(response.First_Line != null)
				{
					OnResponseReady(pair);
				}
			};	
		};
		timer = catcher.Utils.SetInterval(() => {
			lock(_lock)
			{
				if(undisplayed_counter > 0)
				{
					for(int i=items.Count-undisplayed_counter; i<items.Count; i++)
						view.AddItem(items[i]);
					undisplayed_counter = 0;
				}
			}
		}, 500);

		t = new Thread(f => StartCapturingOnANewThread(saved));
		t.Start();


	}

	void StartSniffingDevice(int device)
	{
		capture.StopCapturing();
		capture.StartCapturing(device);
	}

	int GetSavedDevice()
	{
		int device = 0;
		if(File.Exists("params.txt"))
		{
			var p = new List<string>(File.ReadAllLines("params.txt"));
			var d = p.FirstOrDefault(f => f.Trim().ToLower().StartsWith("device_number"));
			if(d != null)
				device = Convert.ToInt32(d.Split(new string[] {"=>"}, StringSplitOptions.RemoveEmptyEntries)[1]);
		}
		return device;
	}
	void SaveDevice(int device)
	{
		using(TextWriter tw = new StreamWriter("params.txt"))
		{
			tw.WriteLine("device_number => {0}", device);
		}
	}
	void OnResponseReady (Pair pair)
	{
		lock (_lock) 
		{
			var item = items.FirstOrDefault (f => f.Pair == pair);		
			if(item != null)
			{
				item.ResponseText = pair.Response.First_Line + "\n" + pair.Response.Headers_String + "\n\n" + pair.Response.Body_String;
				if (pair.Response.Zipping != Zipping.None) 
				{
					item.ResponseText = pair.Response.First_Line + "\n" + pair.Response.Headers_String + "\n\n" + pair.Response.Unzipped_Body;
				} 
				else 
				{
					item.ResponseText = pair.Response.First_Line + "\n" + pair.Response.Headers_String + "\n\n" + pair.Response.Body_String;
				}
				if(pair.Request.Body_Bytes != null)
				{
					item.RequestBody = new List<byte>();
					foreach(var b in pair.Request.Body_Bytes)
						item.RequestBody.Add(b);
				}
				if(pair.Response.Body_Bytes != null)
				{
					item.ResponseBody = new List<byte>();
					foreach(var b in pair.Response.Body_Bytes)
						item.ResponseBody.Add(b);
				}
			}
		}
	}

	public void StartCapturingOnANewThread (int device)
	{
		try 
		{
			StartSniffingDevice(device);
		} 
		catch (Exception ex) 
		{
			if(!(ex is ThreadAbortException))
			{
				Console.Error.WriteLine("ERROR in capturing: Thread stopped: {0} \n {1}", 
						                 ex.InnerException != null ? ex.InnerException.Message : ex.Message,
						                 ex.InnerException != null ? ex.InnerException.StackTrace : ex.StackTrace);	
			}
		}
	}




	protected void OnDeleteEvent (object sender, DeleteEventArgs a)
	{
		a.RetVal = true;
		Exit();
	}

	void Exit()
	{
		capture.StopCapturing ();
		t.Abort ();
		Tcp_packets_holder.StopWorking();
		Application.Quit ();
	}

	protected void OnSaveRequestBodyActionActivated (object sender, EventArgs e)
	{
		if(SelectedItem != null)
		{
			string file_path = null;
			using(FileChooserDialog fc= new FileChooserDialog("Choose the file to save to", this, FileChooserAction.Save, "Cancel", ResponseType.Cancel, "Save", ResponseType.Accept))
			{
				fc.SetCurrentFolder(Directory.GetCurrentDirectory());
				if (fc.Run() == (int)ResponseType.Accept) 
				{
					file_path = fc.Filename;
				}
				else
				{
					file_path = null;
				}
				fc.Destroy();
			}

			if(file_path != null)
			{
				byte[] array;
				lock (_lock)
				{
					array = SelectedItem.RequestBody.ToArray();
				}
				File.WriteAllBytes(file_path, array);
			}
		}
	}

	protected void OnSaveResponseBodyActionActivated (object sender, EventArgs e)
	{
		if(SelectedItem != null)
		{
			string file_path = null;
			using(FileChooserDialog fc= new FileChooserDialog("Choose the file to save to", this, FileChooserAction.Save, "Cancel", ResponseType.Cancel, "Save", ResponseType.Accept))
			{
				fc.SetCurrentFolder(Directory.GetCurrentDirectory());
				if (fc.Run() == (int)ResponseType.Accept) 
				{
					file_path = fc.Filename;
				}
				else
				{
					file_path = null;
				}
				fc.Destroy();
			}
			
			if(file_path != null)
			{
				byte[] array;
				lock (_lock)
				{
					array = SelectedItem.ResponseBody.ToArray();
				}
				File.WriteAllBytes(file_path, array);
			}
		}
	}

	protected void OnAboutActionActivated (object sender, EventArgs e)
	{
		using(AboutDialog about = new AboutDialog())
		{
			about.ProgramName = "Catcher";
			about.Copyright = "http packet viewer for linux, version 0.1 (2013-01-01)";
			about.Website = "https://github.com/ren85/catcher";

			about.Run();
			about.Destroy();
		}
	}

	protected void OnQuitActionActivated (object sender, EventArgs e)
	{
		Exit();
	}


	protected void OnIndexActionActivated (object sender, EventArgs e)
	{
		MessageDialog md = new MessageDialog(this, DialogFlags.DestroyWithParent, MessageType.Info, ButtonsType.Close, capture.GetStatistics());
		md.Title = "Statistics";
		md.Run();
		md.Destroy();
	}
}
