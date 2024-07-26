namespace JWTCoreAPI.Models
{
    public class AuthenticationResult
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public DateTime? expired { get; set; }
    }
}
