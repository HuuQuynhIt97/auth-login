using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

namespace Authentication.Data
{
    public class DataContext : DbContext
    {
        public DbSet<User> Users { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<SystemCode> SystemCodes { get; set; }
        public DbSet<RefreshToken> RefreshToken { get; set; }
        public DbSet<UserSystem> UserSystems { get; set; }
        public DataContext(DbContextOptions<DataContext> options) : base(options) { }
    }
}
