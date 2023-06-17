using Microsoft.AspNetCore.Identity;

namespace XBoilerPlate.Models
{
    public class UserModel : IdentityUser
    {
        public string FirstName { get; set; } = null!;
        public string Surname { get; set; } = null!;
    }
}