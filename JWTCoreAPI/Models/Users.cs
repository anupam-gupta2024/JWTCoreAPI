namespace JWTCoreAPI.Models
{
    public class UserModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string Email { get; set; }
        public string Role { get; set; }
        public string GivenName { get; set; }
        public int expired { get; set; }
        public string Designation { get; set; }
        public string Deptarment { get; set; }
        public string Status { get; set; }
        public string Center { get; set; }
        public string DOJ { get; set; }
    }

    public class Userlogin
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class UserConstants
    {
        public static List<UserModel> Users = new List<UserModel>() {
            new UserModel(){ Username="anupam.gupta", Email="anupam.gupta@allen.in", Password="anupam@123", GivenName="Anupam Gupta", Role="Developer", expired=1440, Designation="Manager",Deptarment="IT&C - Software", Status="NORMAL", Center="KOTA", DOJ="23/04/2018" },
            new UserModel(){ Username="mike", Email="mike@allen.in", Password="mike@123", GivenName="Mike Tyson", Role="Operator", expired=1, Designation="Executive",Deptarment="Human Resources", Status="NORMAL", Center="KOTA", DOJ="01/09/2022" },
            new UserModel(){ Username="john.michael", Email="john.michael@allen.in", Password="john.michael@123", GivenName="John Michael", Role="Projects", expired=1, Designation="Staff Executive",Deptarment="Digital - Multimedia", Status="NORMAL", Center="CHANDIGARH", DOJ="11/11/2022" },
            new UserModel(){ Username="alexa.liras", Email="alexa.liras@allen.in", Password="mike@123", GivenName="Alexa Liras", Role="Organization", expired=1, Designation="Vice President",Deptarment="Accounts & Commercial", Status="HOLD", Center="MUMBAI", DOJ="18/02/2023" },
            new UserModel(){ Username="laurent.perrier", Email="laurent.perrier@allen.in", Password="mike@123", GivenName="Laurent Perrier", Role="Operator", expired=1, Designation="General Manager",Deptarment="Administration", Status="LEFT", Center="GURUGRAM", DOJ="12/05/2008" },
            new UserModel(){ Username="michael.levi", Email="michael.levi@allen.in", Password="mike@123", GivenName="Michael Levi", Role="Executive", expired=1, Designation="Co-Ordinator",Deptarment="Maintenance", Status="NORMAL", Center="AMRITSAR", DOJ="13/06/2016" },
        };
    }
}
