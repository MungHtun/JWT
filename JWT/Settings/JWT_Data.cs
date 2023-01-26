using System;
namespace JWT.Settings
{
	public class JWT_Data
	{
		public string key { get; set; }
		public string Issuer { get; set; }
		public string Audience { get; set; }
		public double DurationInMinutes { get; set; }

	}
}

