using JwtAuthStart.Models;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthStart.Data
{
    public class UsersDbContext : DbContext
    {
        public UsersDbContext(DbContextOptions options) : base(options)
        {
        }
        public DbSet<User> Users { get; set; }
    }
}
