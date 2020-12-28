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
    [Authorize(Roles="Administrator")]
    public class UserController : Controller
    {
        private readonly ILogger<UserController> _logger;
        private readonly ChatContext _context;

        public UserController(ILogger<UserController> logger, ChatContext context)
        {
            _logger = logger;
            _context = context;
        }

        public IActionResult Index()
        {
            var model = _context.Users.Select(m => new UserModel()
            {
                ID = m.ID,
                UserName = m.UserName,
                RoleEnum = m.RoleEnum
            }).ToList();

            return View(model);
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Create(UserModel model)
        {
            if (ModelState.IsValid)
            {
                var existingUser = _context.Users.FirstOrDefault(m => m.UserName == model.UserName);
                if (existingUser != null)
                {
                    ModelState.AddModelError("UserName", "User with this name already exists.");
                }

                if (string.Compare(model.Password, model.ConfirmPassword, false) != 0)
                {
                    ModelState.AddModelError("Password", "Passwords do not match!");
                }

                if (ModelState.IsValid)
                {
                    User newUser = new User();
                    newUser.UserName = model.UserName;
                    newUser.Salt = PasswordHelper.GenerateSalt();
                    newUser.Password = PasswordHelper.GenerateSaltedHash(model.Password, newUser.Salt);
                    newUser.RoleEnum = model.RoleEnum;
                    _context.Users.Add(newUser);
                    _context.SaveChanges();
                    return RedirectToAction("Index", "User");
                }
            }

            return View(model);
        }

        public IActionResult Delete(int id)
        {
            var existingUser = _context.Users.FirstOrDefault(m => m.ID == id);
            if (existingUser == null)
            {
                return RedirectToAction("Index");
            }

            UserModel model = new UserModel();
            model.ID = existingUser.ID;
            model.UserName = existingUser.UserName;
            return View(model);
        }

        [HttpPost]
        public IActionResult Delete(string userName)
        {
            var model = _context.Users.Include(m => m.Messages).FirstOrDefault(m => m.UserName == userName);

            if (string.IsNullOrWhiteSpace(userName))
            {
                ModelState.AddModelError("UserName", "You must provide a user name.");
            }

            if (string.Compare(model.UserName, User.Identity.Name, true) == 0)
            {
                ModelState.AddModelError("UserName", "You cannot delete yourself!");
            }

            if (ModelState.IsValid)
            {
                if (model != null)
                {
                    _context.Messages.RemoveRange(model.Messages);
                    _context.Users.Remove(model);
                    _context.SaveChanges();
                    return RedirectToAction("Index");
                }
            }

            return View();
        }
    }
}
