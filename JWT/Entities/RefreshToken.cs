using System;
using Microsoft.EntityFrameworkCore;

namespace JWT.Entities
{
    [Owned]
    public class RefreshToken
	{
		public string Token { get; set; }
        public DateTime Exprires { get; set; }
        public bool IsExpired => DateTime.UtcNow >= Exprires;
        public DateTime Created { get; set; }
        public DateTime? Revoked { get; set; }
        public bool IsActive => Revoked == null && !IsExpired;
    }
}

