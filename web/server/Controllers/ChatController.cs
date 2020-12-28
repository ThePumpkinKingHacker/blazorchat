using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using web.Models;
using web.Classes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

namespace web.Controllers
{
    [Authorize(Roles="Administrator,User")]
    public class ChatController : Controller
    {
        private readonly ILogger<ChatController> _logger;
        private readonly ChatContext _context;

        public ChatController(ILogger<ChatController> logger, ChatContext context)
        {
            _logger = logger;
            _context = context;
        }

        public IActionResult Index()
        {
            var messages = _context.Messages.OrderByDescending(m=>m.Timestamp).Take(100).Include(m => m.User).Select(m => new MessageModel()
            {
                Content = m.Content,
                Date = m.Timestamp,
                UserName = m.User.UserName
            }).ToList();

            return View(messages);
        }
    }
}
