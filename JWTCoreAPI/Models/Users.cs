namespace JWTCoreAPI.Models
{
    public class UserModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string Email { get; set; }
        public string Role { get; set; }
        public string GivenName { get; set; }
    }

    public class Userlogin
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class UserConstants
    {
        public static List<UserModel> Users = new List<UserModel>() {
            new UserModel(){ Username="anupam.gupta", Email="anupam.gupta@allen.in", Password="anupam@123", GivenName="Anupam Gupta", Role="Developer"},
            new UserModel(){ Username="mike", Email="mike@allen.in", Password="mike@123", GivenName="Mike Tyson", Role="Operator"}
        };
    }
}
