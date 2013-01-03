using System;

namespace catcher
{
	public class Utils
	{
		public static System.Timers.Timer SetInterval(Action method, int delayInMilliseconds)
		{
			System.Timers.Timer timer = new System.Timers.Timer(delayInMilliseconds);
			timer.Elapsed += (source, e) =>
			{
				method();
			};
			
			timer.Enabled = true;
			timer.Start();
			
			// Returns a stop handle which can be used for stopping
			// the timer, if required
			return timer;
		}
		
		public static System.Timers.Timer SetTimeout(Action method, int delayInMilliseconds)
		{
			System.Timers.Timer timer = new System.Timers.Timer(delayInMilliseconds);
			timer.Elapsed += (source, e) =>
			{
				method();
			};
			
			timer.AutoReset = false;
			timer.Enabled = true;
			timer.Start();
			
			// Returns a stop handle which can be used for stopping
			// the timer, if required
			return timer;
		}
	}
}

