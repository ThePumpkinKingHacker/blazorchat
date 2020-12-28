using System;
using System.ComponentModel.DataAnnotations;

public class SetupModel
{
    [Required]
    [StringLength(100)]
    public string SetupSecret { get; set; }

    [Required]
    [StringLength(50)]
    public string UserName { get; set; }

    [Required]
    [StringLength(50)]
    public string Password { get; set; }

    [Required]
    [StringLength(50)]
    public string ConfirmPassword { get; set; }
}