using System;
using Gtk;

namespace catcher
{
	class MainClass
	{
		public static void Main (string[] args)
		{

			Application.Init ();
			MainWindow win = new MainWindow ();
			win.Show ();
			win.Maximize();
			Application.Run ();
		}
	}
}
