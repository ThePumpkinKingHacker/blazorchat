using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;

namespace web.Classes
{
    public class ChatContext : DbContext
    {
        public DbSet<User> Users { get; set; }
        public DbSet<Message> Messages { get; set; }

        public ChatContext(DbContextOptions<ChatContext> options) : base(options)
        {

        }
    }

    public class User
    {
        public int ID { get; set; }
        public string UserName { get; set; }
        public byte[] Password { get; set; }
        public byte[] Salt { get; set; }
        public byte RoleEnum { get; set; }
        public List<Message> Messages { get; } = new List<Message>();
    }

    public class Message
    {
        public int ID { get; set; }
        public DateTime Timestamp { get; set; }
        public string Content { get; set; }
        public int UserID { get; set; }
        public User User { get; set; }
    }
}