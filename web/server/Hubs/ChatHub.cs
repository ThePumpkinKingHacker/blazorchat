using Ganss.XSS;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.SignalR;
using System.Threading.Tasks;
using web.Classes;
using System.Linq;
using System;
using Microsoft.AspNetCore.Authorization;

namespace web.Hubs
{
    [Authorize(Roles="Administrator,User")]
    public class ChatHub : Hub
    {
        private readonly ChatContext _context;

        public ChatHub(ChatContext context)
        {
            _context = context;
        }

        public async Task SendMessage(string message)
        {
            var sanitizer = new HtmlSanitizer();
            var sanitized = sanitizer.Sanitize(message);

            var existingUser = _context.Users.FirstOrDefault(m => m.UserName == Context.User.Identity.Name);
            var date = DateTime.Now;

            existingUser.Messages.Add(new Message()
            {
                Content = sanitized,
                Timestamp = date
            });

            _context.SaveChanges();
            await Clients.All.SendAsync("ReceiveMessage", Context.User.Identity.Name, date.ToString(), sanitized);
        }
    }
}