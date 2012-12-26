using System;
using Gtk;
using System.Collections;
using catcher;
using pcap;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using Pango;

class ItemModel
{
	public string Number { get; set; }
	public string Status { get; set; }
	public string Protocol { get; set; }
	public string Host { get; set; }
	public string Url { get; set; }

	public Pair Pair { get; set; }
	public string RequestText { get; set; }
	public string ResponseText { get; set; }
}

class ItemsView : MyListView<ItemModel>
{
	public ItemsView () : base("#", "Status", "Protocol", "Host", "Url")
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
			case 1:
				render.Text = item.Status;
				break;
			case 2:
				render.Text = item.Protocol;
				break;
			case 3:
				render.Text = item.Host;
				break;
			case 4:
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
		/*view.KeyPressEvent += (object o, KeyPressEventArgs args) => 
		{
			if (args.Event.Key == Gdk.Key.Delete)
			{
				var s_items = view.SelectedItems.ToList<ItemModel>();
				foreach(var i in s_items)
				{
					view.RemoveItem(i);
					items.Remove(i);
					//Capturing.Pairs.Pairs[i.Index] = new Pair() {Request = new Request(), Response = new Response()};
				}
			}
		};*/
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
			}
		};

		Tcp_packets_holder.StartWorking();
		StartCapturing();
	}

	void StartCapturing()
	{
		capture = new Capturing ();
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
			lock(_lock)
			{
				items.Add(item);
				undisplayed_counter++;
			}
		};
		
		Tcp_packets_holder.Pairs.OnNewResponse += (pair) => 
		{
			var response = pair.Response;
			if(response.IsCompleted)
			{
				OnResponseReady(pair);
			}
			else
			{
				response.OnBytesAdded += () => 
				{
					if(response.Headers_String != null)
					{
						OnResponseReady(pair);
					}
				};	
			}
		};
		catcher.Utils.SetInterval(() => {
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
		t = new Thread(f => StartCapturingOnANewThread());
		t.Start();
	}

	void OnResponseReady (Pair pair)
	{
		lock (_lock) 
		{
			var item = items.Single (f => f.Pair == pair);		
			item.ResponseText = pair.Response.First_Line + "\n" + pair.Response.Headers_String + "\n\n" + pair.Response.Body_String;
			if (pair.Response.Zipping != Zipping.None) 
			{
				item.ResponseText = pair.Response.First_Line + "\n" + pair.Response.Headers_String + "\n\n" + pair.Response.Unzipped_Body;
			} 
			else 
			{
				item.ResponseText = pair.Response.First_Line + "\n" + pair.Response.Headers_String + "\n\n" + pair.Response.Body_String;
			}
		}
	}

	public void StartCapturingOnANewThread ()
	{
		try 
		{
			capture.StartCapturing(0);
		} 
		catch (Exception ex) 
		{
			Console.WriteLine("ERROR in capturing: Thread stopped: {0} \n {1}", 
			                  ex.InnerException != null ? ex.InnerException.Message : ex.Message,
			                  ex.InnerException != null ? ex.InnerException.StackTrace : ex.StackTrace);		
		}
	}




	protected void OnDeleteEvent (object sender, DeleteEventArgs a)
	{
		capture.StopCapturing ();
		t.Abort ();
		Tcp_packets_holder.StopWorking();
		Application.Quit ();
		a.RetVal = true;
	}

}
