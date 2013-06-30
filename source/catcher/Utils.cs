using System;

namespace catcher
{
	public class Utils
	{
		public static void SetInterval(Action method, int delayInMilliseconds)
		{
//			System.Timers.Timer timer = new System.Timers.Timer(delayInMilliseconds);
//			timer.Elapsed += (source, e) =>
//			{
//				method();
//			};
//			
//			timer.Enabled = true;
//			timer.Start();
//			
//			// Returns a stop handle which can be used for stopping
//			// the timer, if required
//			return timer;

			GLib.Timeout.Add((uint)delayInMilliseconds, () => 
            {
				method();
				return true;
			});
		}
		
//		public static System.Timers.Timer SetTimeout(Action method, int delayInMilliseconds)
//		{
//			System.Timers.Timer timer = new System.Timers.Timer(delayInMilliseconds);
//			timer.Elapsed += (source, e) =>
//			{
//				method();
//			};
//			
//			timer.AutoReset = false;
//			timer.Enabled = true;
//			timer.Start();
//			
//			// Returns a stop handle which can be used for stopping
//			// the timer, if required
//			return timer;
//		}
	}
}

