using System;
using System.ComponentModel.DataAnnotations;

public class UserModel
{
    public int ID { get; set; }

    [Required]
    [StringLength(50)]
    public string UserName { get; set; }

    [Required]
    public byte RoleEnum { get; set; }

    [Required]
    [StringLength(100)]
    public string Password { get; set; }

    [Required]
    [StringLength(100)]
    public string ConfirmPassword { get; set; }
}