using System;
using System.ComponentModel.DataAnnotations;

public class MessageModel
{
    public string UserName { get; set; }
    public string Content { get; set; }
    public DateTime Date { get; set; }
}