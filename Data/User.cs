using Microsoft.AspNetCore.Identity;

namespace AuthenticationDemo.Data
{
    public class User: IdentityUser
    {
        public string Name { get; set; }
    }
}
