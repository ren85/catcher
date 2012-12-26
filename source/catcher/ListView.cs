using System;
using System.Collections.Generic;
using Gtk;


namespace catcher
{
	[System.ComponentModel.ToolboxItem(true)]
	public partial class ListView : Gtk.Bin
	{
		public ListView ()
		{
			this.Build();
		}
	}

	/// <summary>
	/// <para>A single column list, text comes from object.ToString()</para>
	/// <para>For multicolumns, see ListView&lt;ClassType&gt;</para>
	/// </summary>
	public class MyListView : MyListView<object>
	{
		public MyListView (string columnTitle) : base(columnTitle)
		{
		}
		
		protected override void RenderCell (CellRendererText render, int index, object item)
		{
			render.Text = item.ToString ();
		}
	}
	
	/// <summary>
	/// The list only contains one type of object.
	/// To get multiple columns, pass that number of parameters to the constructor
	/// and implement RenderCell accordingly.
	/// </summary>
	public abstract class MyListView<T> : TreeView
	{
		/// <summary>
		/// List of all items selected
		/// </summary>
		public T[] SelectedItems { get; private set; }
		public event Action<T[]> ItemSelected;
		public event Action<T> ItemActivated;
		
		protected abstract void RenderCell (CellRendererText render, int index, T item);
		
		ListStore store = new ListStore (typeof(T));
		Dictionary<T, TreeIter> storeList = new Dictionary<T, TreeIter> ();
		List<TreeViewColumn> columns = new List<TreeViewColumn> ();
		
		/// <summary>
		/// Pass one string parameter for every column
		/// </summary>
		/// <param name="columnNames">
		/// Column Titles, one parameter for each column.
		/// </param>
		public MyListView (params string[] columnNames)
		{
			this.Model = store;
			foreach (string s in columnNames) {
				TreeViewColumn c = this.AppendColumn (s, new CellRendererText (), this.ColumnCellData);
				c.Resizable = true;
				columns.Add (c);
			}
			
			this.SelectedItems = new T[0];
			this.Selection.Changed += HandleSelectionChanged;

		}
		
		private void ColumnCellData (TreeViewColumn column, CellRenderer renderer, TreeModel model, TreeIter iter)
		{
			T item = (T)model.GetValue (iter, 0);
			CellRendererText textRender = (CellRendererText)renderer;
			int index = columns.IndexOf (column);
			RenderCell (textRender, index, item);
		}
		
		#region Add, Remove and Clear Items
		
		public void AddItem (T item)
		{
			var iter = store.AppendValues (item);
			//store.EmitRowInserted(Model.GetPath(iter), iter);
			storeList.Add (item, iter);
		}
		
		public void ClearItems ()
		{
			store.Clear ();
			storeList.Clear ();
		}
		
		public void RemoveItem (T item)
		{
			if (!storeList.ContainsKey (item))
				return;
			
			TreeIter iter = storeList[item];
			store.Remove (ref iter);
			storeList.Remove (item);
		}
		
		#endregion
		
		#region Selection and Aktivation triggers
		
		void HandleSelectionChanged (object sender, EventArgs e)
		{
			TreeSelection selection = (TreeSelection)sender;
			TreePath[] paths = selection.GetSelectedRows ();
			T[] items = new T[paths.Length];
			for (int n = 0; n < paths.Length; n++) {
				TreeIter iter;
				Model.GetIter (out iter, paths[n]);
				items[n] = (T)Model.GetValue (iter, 0);
			}
			
			SelectedItems = items;
			
			var itemEvent = ItemSelected;
			if (itemEvent != null)
				itemEvent (items);
		}
		
		protected override void OnRowActivated (TreePath path, TreeViewColumn column)
		{
			TreeIter iter;
			Model.GetIter (out iter, path);
			T item = (T)Model.GetValue (iter, 0);
			
			var e = ItemActivated;
			if (e != null)
				e (item);
			
			base.OnRowActivated (path, column);
		}
		
		#endregion
	}
}

